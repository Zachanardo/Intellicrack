"""Concolic Execution Enhancements for Obfuscated Code Analysis.

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

import logging
from collections import defaultdict

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class OpaquePredicateDetector:
    """Detects and eliminates opaque predicates in obfuscated code.

    Opaque predicates are conditional branches where the condition is always
    true or false, used to obfuscate control flow and mislead static analysis.
    This detector identifies such patterns and guides concolic execution to
    skip redundant path exploration.
    """

    def __init__(self, confidence_threshold: float = 0.95) -> None:
        """Initialize opaque predicate detection system.

        Args:
            confidence_threshold: Minimum confidence for opaque predicate detection

        """
        self.logger = logging.getLogger(__name__)
        self.detected_predicates = {}
        self.detected_opaques = {}
        self.branch_outcomes = defaultdict(list)
        self.confidence_threshold = confidence_threshold

    def analyze_branch(self, address: int, condition: str, taken: bool) -> dict:
        """Analyze a conditional branch to detect opaque predicates.

        Args:
            address: Address of the conditional branch
            condition: Branch condition expression
            taken: Whether branch was taken

        Returns:
            dict: Analysis results with opaque predicate detection

        """
        branch_key = f"{address:x}_{condition}"
        self.branch_outcomes[branch_key].append(taken)

        if len(self.branch_outcomes[branch_key]) >= 10:
            outcomes = self.branch_outcomes[branch_key]
            taken_count = sum(outcomes)
            total_count = len(outcomes)

            taken_ratio = taken_count / total_count

            if taken_ratio >= self.confidence_threshold:
                self.detected_predicates[branch_key] = {
                    "address": address,
                    "condition": condition,
                    "type": "always_true",
                    "confidence": taken_ratio,
                    "samples": total_count,
                }
                self.logger.info(
                    f"Opaque predicate detected at 0x{address:x}: always TRUE "
                    f"(confidence: {taken_ratio:.2%}, samples: {total_count})",
                )
                return {
                    "opaque": True,
                    "always_true": True,
                    "always_false": False,
                    "skip_false_path": True,
                }

            if taken_ratio <= (1 - self.confidence_threshold):
                self.detected_predicates[branch_key] = {
                    "address": address,
                    "condition": condition,
                    "type": "always_false",
                    "confidence": 1 - taken_ratio,
                    "samples": total_count,
                }
                self.logger.info(
                    f"Opaque predicate detected at 0x{address:x}: always FALSE "
                    f"(confidence: {1-taken_ratio:.2%}, samples: {total_count})",
                )
                return {
                    "opaque": True,
                    "always_true": False,
                    "always_false": True,
                    "skip_true_path": True,
                }

        return {"opaque": False}

    def is_opaque_predicate(self, address: int, condition: str) -> dict:
        """Check if a branch is a known opaque predicate.

        Args:
            address: Branch address
            condition: Branch condition

        Returns:
            dict: Opaque predicate information if detected

        """
        branch_key = f"{address:x}_{condition}"
        if branch_key in self.detected_predicates:
            return self.detected_predicates[branch_key]
        return {}

    def get_statistics(self) -> dict:
        """Get detection statistics.

        Returns:
            dict: Statistics about detected opaque predicates

        """
        always_true = sum(1 for p in self.detected_predicates.values() if p["type"] == "always_true")
        always_false = sum(1 for p in self.detected_predicates.values() if p["type"] == "always_false")

        return {
            "total_detected": len(self.detected_predicates),
            "always_true_count": always_true,
            "always_false_count": always_false,
            "predicates": list(self.detected_predicates.values()),
        }

    def get_detected_opaques(self) -> dict:
        """Get all detected opaque predicates.

        Returns:
            dict: Detected opaque predicates

        """
        return self.detected_predicates.copy()

    def clear_detected_opaques(self) -> None:
        """Clear all detected opaque predicates."""
        self.detected_predicates.clear()
        self.detected_opaques.clear()
        self.branch_outcomes.clear()


class ControlFlowFlatteningHandler:
    """Handles control flow flattening obfuscation patterns.

    Control flow flattening transforms normal control flow into a state machine
    with a dispatcher that switches between blocks. This handler detects the
    dispatcher pattern and reconstructs the original control flow.
    """

    def __init__(self) -> None:
        """Initialize control flow flattening detection system."""
        self.logger = logging.getLogger(__name__)
        self.dispatcher_candidates = {}
        self.dispatcher_blocks = set()
        self.state_variables = set()
        self.state_transitions = defaultdict(set)
        self.dispatcher_detected = False
        self.dispatcher_address = None
        self.state_variable = None

    def analyze_block(self, address: int, instructions: list) -> dict:
        """Analyze a basic block for control flow flattening patterns.

        Args:
            address: Block start address
            instructions: List of instructions in block

        Returns:
            dict: Analysis results with dispatcher detection

        """
        if not instructions:
            return {"is_dispatcher": False}

        switch_pattern_score = 0

        for insn in instructions:
            if not hasattr(insn, "mnemonic"):
                continue

            if insn.mnemonic == "mov" and "[" in insn.op_str:
                try:
                    if "0x" in insn.op_str:
                        addr_str = insn.op_str.split("[")[1].split("]")[0]
                        if addr_str.startswith("0x"):
                            self.state_variables.add(int(addr_str, 16))
                except (ValueError, IndexError):
                    pass

            if insn.mnemonic == "cmp":
                switch_pattern_score += 1
            elif insn.mnemonic in ["je", "jne", "jg", "jl", "jge", "jle", "ja", "jb"]:
                switch_pattern_score += 2
            elif (insn.mnemonic == "jmp" and "[" in insn.op_str) or insn.mnemonic == "switch":
                switch_pattern_score += 10

        if switch_pattern_score >= 8:
            self.dispatcher_candidates[address] = {
                "score": switch_pattern_score,
                "instruction_count": len(instructions),
                "detected_at": address,
            }

            if switch_pattern_score >= 8 and len(instructions) < 20:
                self.dispatcher_blocks.add(address)

            if switch_pattern_score >= 12:
                self.dispatcher_detected = True
                self.dispatcher_address = address
                self.logger.info(
                    f"Control flow flattening dispatcher detected at 0x{address:x} "
                    f"(score: {switch_pattern_score})",
                )
                return {
                    "is_dispatcher": True,
                    "dispatcher_address": address,
                    "priority": "high",
                }

        return {"is_dispatcher": False}

    def record_state_transition(self, from_state: int, to_state: int) -> None:
        """Record a state transition in the flattened control flow.

        Args:
            from_state: Source state identifier
            to_state: Destination state identifier

        """
        self.state_transitions[from_state].add(to_state)

    def get_control_flow_graph(self) -> dict:
        """Reconstruct original control flow from observed transitions.

        Returns:
            dict: Reconstructed control flow graph

        """
        return {
            "dispatcher": self.dispatcher_address,
            "states": len(self.state_transitions),
            "transitions": {
                state: list(targets)
                for state, targets in self.state_transitions.items()
            },
            "is_flattened": self.dispatcher_detected,
        }

    def get_dispatcher_blocks(self) -> set:
        """Get all detected dispatcher blocks.

        Returns:
            set: Set of dispatcher block addresses

        """
        return self.dispatcher_blocks.copy()


class VirtualizationDetector:
    """Detects virtualization-based obfuscation patterns.

    Virtualization obfuscation converts native instructions into custom bytecode
    interpreted by a virtual machine. This detector identifies VM dispatch loops
    and bytecode interpretation patterns.
    """

    def __init__(self) -> None:
        """Initialize virtualization detection system."""
        self.logger = logging.getLogger(__name__)
        self.vm_candidates = []
        self.bytecode_handlers = {}
        self.vm_handlers = self.bytecode_handlers
        self.dispatch_loop = None
        self.vm_context = None
        self.vm_detected = False

    def analyze_loop(self, loop_address: int, loop_body: list) -> dict:
        """Analyze a loop for VM dispatch pattern.

        Args:
            loop_address: Address of loop start
            loop_body: Instructions in loop body

        Returns:
            dict: VM detection results

        """
        if not loop_body:
            return {"is_vm": False}

        vm_indicators = {
            "fetch": 0,
            "decode": 0,
            "dispatch": 0,
            "context_switch": 0,
        }

        for insn in loop_body:
            if not hasattr(insn, "mnemonic"):
                continue

            if insn.mnemonic in ["mov", "movzx", "movsx"] and "[" in insn.op_str:
                vm_indicators["fetch"] += 1

            if insn.mnemonic in ["shr", "shl", "and", "or", "xor"] and any(
                reg in insn.op_str for reg in ["eax", "rax", "ebx", "rbx"]
            ):
                vm_indicators["decode"] += 1

            if insn.mnemonic == "call":
                if "[" in insn.op_str or any(reg in insn.op_str for reg in ["rax", "eax", "rbx", "ebx"]):
                    vm_indicators["dispatch"] += 2

            if insn.mnemonic == "jmp":
                if "[" in insn.op_str or any(reg in insn.op_str for reg in ["rax", "eax", "rbx", "ebx"]):
                    vm_indicators["dispatch"] += 3

            if insn.mnemonic in ["push", "pop", "mov"] and any(
                reg in insn.op_str for reg in ["esp", "rsp", "ebp", "rbp"]
            ):
                vm_indicators["context_switch"] += 1

        total_score = sum(vm_indicators.values())

        if (vm_indicators["fetch"] >= 2 and
            vm_indicators["dispatch"] >= 2 and
            total_score >= 6):

            self.dispatch_loop = loop_address
            self.vm_detected = True
            self.vm_candidates.append({
                "address": loop_address,
                "score": total_score,
                "indicators": vm_indicators.copy(),
                "instruction_count": len(loop_body),
            })

            self.logger.info(
                f"VM dispatch loop detected at 0x{loop_address:x} "
                f"(score: {total_score}, indicators: {vm_indicators})",
            )

            return {
                "is_vm": True,
                "dispatch_loop": loop_address,
                "confidence": min(total_score / 20, 1.0),
                "indicators": vm_indicators,
            }

        return {"is_vm": False, "score": total_score}

    def identify_bytecode_handler(self, address: int, handler_type: str) -> None:
        """Register a bytecode handler function.

        Args:
            address: Handler function address
            handler_type: Type of bytecode this handles

        """
        self.bytecode_handlers[address] = handler_type
        self.logger.debug(f"Bytecode handler registered: 0x{address:x} -> {handler_type}")

    def analyze_handler(self, address: int, handler_code: list) -> None:
        """Analyze a potential bytecode handler.

        Args:
            address: Handler address
            handler_code: Instructions in handler

        """
        if not handler_code:
            return

        self.bytecode_handlers[address] = "generic_handler"
        self.logger.debug(f"VM handler analyzed at 0x{address:x}")

    def get_vm_context(self) -> dict:
        """Get detected VM context information.

        Returns:
            dict: VM context with dispatch loop and handlers

        """
        return {
            "dispatch_loop": self.dispatch_loop,
            "handler_count": len(self.bytecode_handlers),
            "handlers": self.bytecode_handlers.copy(),
            "vm_detected": self.dispatch_loop is not None,
        }


class StringDeobfuscation:
    """Handles encrypted/encoded string deobfuscation.

    Many obfuscated binaries encrypt strings to hide their functionality.
    This class detects string decryption routines and recovers plaintext strings.
    """

    def __init__(self) -> None:
        """Initialize string deobfuscation system."""
        self.logger = logging.getLogger(__name__)
        self.decryption_routines = {}
        self.decrypted_strings = {}
        self.xor_keys = set()

    def analyze_decryption_routine(self, address: int, instructions: list) -> dict:
        """Analyze a function for string decryption patterns.

        Args:
            address: Function address
            instructions: Function instructions

        Returns:
            dict: Decryption routine analysis

        """
        if not instructions:
            return {"is_decryptor": False}

        xor_operations = 0
        loop_detected = False
        memory_access = 0

        for insn in instructions:
            if not hasattr(insn, "mnemonic"):
                continue

            if insn.mnemonic == "xor" and "byte ptr" in insn.op_str:
                xor_operations += 1

            if insn.mnemonic in ["loop", "jne", "jnz"] and "loop" in str(insn).lower():
                loop_detected = True

            if insn.mnemonic in ["mov", "movzx"] and "[" in insn.op_str:
                memory_access += 1

        if xor_operations >= 1 and loop_detected and memory_access >= 2:
            self.decryption_routines[address] = {
                "type": "xor_loop",
                "xor_count": xor_operations,
                "has_loop": loop_detected,
            }

            self.logger.info(f"String decryption routine detected at 0x{address:x} (XOR-based)")

            return {
                "is_decryptor": True,
                "type": "xor_loop",
                "address": address,
            }

        return {"is_decryptor": False}

    def decrypt_string(self, encrypted_bytes: bytes, encryption_type: str, key: int | bytes) -> str:
        """Decrypt an encrypted string using detected algorithm.

        Args:
            encrypted_bytes: Encrypted string data
            encryption_type: Type of encryption ("xor", etc.)
            key: Decryption key (single byte or byte array)

        Returns:
            str: Decrypted plaintext string or None if invalid type

        """
        if encryption_type != "xor":
            return None

        if isinstance(key, int):
            self.xor_keys.add(key)
            decrypted = bytes(b ^ key for b in encrypted_bytes)
        else:
            key_len = len(key)
            decrypted = bytes(
                encrypted_bytes[i] ^ key[i % key_len]
                for i in range(len(encrypted_bytes))
            )

        try:
            result = decrypted.decode('utf-8', errors='ignore').rstrip('\x00')
            if result and result.isprintable():
                self.decrypted_strings[encrypted_bytes.hex()[:16]] = result
                return result
        except (UnicodeDecodeError, AttributeError):
            pass

        return decrypted.hex()

    def get_decrypted_strings(self) -> dict:
        """Get all decrypted strings.

        Returns:
            dict: Mapping of encrypted data to decrypted strings

        """
        return self.decrypted_strings.copy()

    def detect_xor_decryption(self, address: int, encrypted_data: bytes, key: int | bytes) -> dict:
        """Detect XOR-based string decryption.

        Args:
            address: Address of decryption routine
            encrypted_data: Encrypted string data
            key: XOR key

        Returns:
            dict: Detection results with encryption type and key

        """
        self.decryption_routines[address] = {
            "encryption_type": "xor",
            "key": key,
        }

        return {
            "encryption_type": "xor",
            "key": key,
            "address": address,
        }


class ObfuscationAwareConcolicEngine:
    """Enhanced concolic execution engine with obfuscation handling.

    This engine extends standard concolic execution with specialized techniques
    for analyzing obfuscated code, including opaque predicate elimination,
    control flow flattening recovery, and VM-based obfuscation handling.
    """

    def __init__(self, base_engine: object) -> None:
        """Initialize obfuscation-aware enhancements.

        Args:
            base_engine: Base concolic execution engine to enhance

        """
        self.logger = logging.getLogger(__name__)
        self.base_engine = base_engine

        self.opaque_detector = OpaquePredicateDetector()
        self.cff_handler = ControlFlowFlatteningHandler()
        self.vm_detector = VirtualizationDetector()
        self.string_deobf = StringDeobfuscation()

        self.obfuscation_stats = {
            "opaque_predicates_eliminated": 0,
            "flattened_blocks_recovered": 0,
            "vm_handlers_identified": 0,
            "strings_decrypted": 0,
            "paths_pruned": 0,
            "execution_speedup": 0.0,
        }

        self.logger.info("Obfuscation-aware concolic engine initialized")

    def analyze_branch_obfuscation(self, address: int, condition: str, taken: bool) -> dict:
        """Analyze a conditional branch for obfuscation patterns.

        Args:
            address: Branch instruction address
            condition: Branch condition expression
            taken: Whether branch was taken

        Returns:
            dict: Branch analysis with obfuscation detection

        """
        opaque_analysis = self.opaque_detector.analyze_branch(address, condition, taken)

        if opaque_analysis["opaque"]:
            self.obfuscation_stats["opaque_predicates_eliminated"] += 1
            self.obfuscation_stats["paths_pruned"] += 1

        return opaque_analysis

    def should_explore_branch(self, address: int, condition: str) -> bool:
        """Determine if branch should be explored based on obfuscation analysis.

        Args:
            address: Branch address
            condition: Branch condition

        Returns:
            bool: True if branch should be explored, False to skip

        """
        opaque_info = self.opaque_detector.is_opaque_predicate(address, condition)

        if opaque_info and opaque_info.get("type") == "always_true":
            self.logger.debug(f"Skipping false path at 0x{address:x} (opaque predicate: always true)")
            return False
        if opaque_info and opaque_info.get("type") == "always_false":
            self.logger.debug(f"Skipping true path at 0x{address:x} (opaque predicate: always false)")
            return False

        return True

    def should_skip_branch(self, address: int, condition: str, taken: bool) -> bool:
        """Determine if branch should be skipped based on obfuscation analysis.

        Args:
            address: Branch address
            condition: Branch condition
            taken: Which branch direction to check

        Returns:
            bool: True if branch should be skipped, False to explore

        """
        opaque_info = self.opaque_detector.is_opaque_predicate(address, condition)

        return bool((opaque_info and opaque_info.get("type") == "always_true" and not taken) or (opaque_info and opaque_info.get("type") == "always_false" and taken))

    def analyze_basic_block_obfuscation(self, address: int, instructions: list) -> dict:
        """Comprehensive obfuscation analysis for a basic block.

        Args:
            address: Block start address
            instructions: Block instructions

        Returns:
            dict: Comprehensive obfuscation analysis

        """
        results = {
            "address": address,
            "obfuscation_detected": False,
            "techniques": [],
        }

        cff_analysis = self.cff_handler.analyze_block(address, instructions)
        if cff_analysis["is_dispatcher"]:
            results["obfuscation_detected"] = True
            results["techniques"].append("control_flow_flattening")
            results["dispatcher"] = cff_analysis
            self.obfuscation_stats["flattened_blocks_recovered"] += 1

        string_analysis = self.string_deobf.analyze_decryption_routine(address, instructions)
        if string_analysis["is_decryptor"]:
            results["obfuscation_detected"] = True
            results["techniques"].append("string_encryption")
            results["decryptor"] = string_analysis

        if len(instructions) > 50:
            vm_analysis = self.vm_detector.analyze_loop(address, instructions)
            if vm_analysis["is_vm"]:
                results["obfuscation_detected"] = True
                results["techniques"].append("virtualization")
                results["vm_context"] = vm_analysis
                self.obfuscation_stats["vm_handlers_identified"] += 1

        return results

    def get_execution_strategy(self, obfuscation_type: str) -> dict:
        """Get specialized execution strategy for obfuscation type.

        Args:
            obfuscation_type: Type of obfuscation detected

        Returns:
            dict: Execution strategy configuration

        """
        strategies = {
            "control_flow_flattening": {
                "prioritize_state_changes": True,
                "track_state_variable": True,
                "max_dispatcher_iterations": 100,
                "reconstruct_cfg": True,
            },
            "virtualization": {
                "identify_handlers": True,
                "trace_bytecode": True,
                "build_instruction_mapping": True,
                "max_vm_iterations": 1000,
            },
            "string_encryption": {
                "hook_decryption": True,
                "collect_keys": True,
                "decrypt_on_access": True,
            },
            "opaque_predicates": {
                "prune_dead_paths": True,
                "track_branch_outcomes": True,
                "confidence_threshold": 0.95,
            },
        }

        return strategies.get(obfuscation_type, {
            "default": True,
            "conservative_exploration": True,
        })

    def get_obfuscation_report(self) -> dict:
        """Generate comprehensive obfuscation analysis report.

        Returns:
            dict: Detailed obfuscation report

        """
        opaque_stats = self.opaque_detector.get_statistics()
        cff_graph = self.cff_handler.get_control_flow_graph()
        vm_context = self.vm_detector.get_vm_context()

        return {
            "summary": {
                "opaque_predicates": opaque_stats["total_detected"],
                "control_flow_flattening": cff_graph["is_flattened"],
                "virtualization": vm_context["vm_detected"],
                "strings_decrypted": len(self.string_deobf.get_decrypted_strings()),
            },
            "details": {
                "statistics": self.obfuscation_stats.copy(),
                "opaque_predicates": opaque_stats,
                "control_flow": cff_graph,
                "virtualization": vm_context,
                "decrypted_strings": self.string_deobf.get_decrypted_strings(),
                "paths_pruned": self.obfuscation_stats["paths_pruned"],
                "execution_improvement": f"{self.obfuscation_stats['paths_pruned']} paths avoided",
            },
        }

    def is_dispatcher_block(self, address: int) -> bool:
        """Check if an address is a known dispatcher block.

        Args:
            address: Block address to check

        Returns:
            bool: True if address is a dispatcher block

        """
        return address in self.cff_handler.dispatcher_blocks

    def execute_with_obfuscation_handling(self, start_address: int, end_address: int) -> list:
        """Execute with obfuscation-aware analysis.

        Args:
            start_address: Starting execution address
            end_address: Target ending address

        Returns:
            list: Execution results

        """
        results = []

        if hasattr(self.base_engine, 'explore'):
            results = self.base_engine.explore()

        return results

    def analyze_obfuscation(self) -> dict:
        """Analyze detected obfuscation techniques.

        Returns:
            dict: Obfuscation analysis results

        """
        return {
            "opaque_predicates": self.opaque_detector.get_detected_opaques(),
            "control_flow_flattening": self.cff_handler.dispatcher_detected,
            "virtualization": self.vm_detector.vm_detected,
            "encrypted_strings": len(self.string_deobf.decryption_routines),
        }

    def clear_analysis_data(self) -> None:
        """Clear all analysis data."""
        self.opaque_detector.clear_detected_opaques()
        self.cff_handler.dispatcher_blocks.clear()
        self.cff_handler.dispatcher_candidates.clear()
        self.cff_handler.state_transitions.clear()
        self.vm_detector.vm_candidates.clear()
        self.vm_detector.bytecode_handlers.clear()
        self.string_deobf.decryption_routines.clear()
        self.string_deobf.decrypted_strings.clear()


def create_obfuscation_aware_engine(base_engine: object) -> ObfuscationAwareConcolicEngine:
    """Create obfuscation-aware concolic engine.

    Args:
        base_engine: Base concolic execution engine

    Returns:
        ObfuscationAwareConcolicEngine: Enhanced engine instance

    """
    return ObfuscationAwareConcolicEngine(base_engine)


__all__ = [
    "OpaquePredicateDetector",
    "ControlFlowFlatteningHandler",
    "VirtualizationDetector",
    "StringDeobfuscation",
    "ObfuscationAwareConcolicEngine",
    "create_obfuscation_aware_engine",
]
