"""Radare2 ESIL (Evaluable Strings Intermediate Language) analysis module."""

import logging
import time
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.tools.radare2_utils import R2Exception, R2Session, r2_session


"""
Radare2 ESIL (Evaluable Strings Intermediate Language) Analysis Engine

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


class ESILAnalysisEngine:
    """Advanced ESIL analysis engine for dynamic binary analysis and emulation.

    Provides sophisticated emulation capabilities for:
    - License validation routine analysis
    - Vulnerability detection through dynamic analysis
    - API behavior monitoring
    - Memory access pattern analysis
    - Register state tracking
    """

    def __init__(self, binary_path: str, radare2_path: str | None = None) -> None:
        """Initialize ESIL analysis engine.

        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable

        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.emulation_cache = {}

    def initialize_esil_vm(self, r2: R2Session) -> bool:
        """Initialize ESIL virtual machine with optimal settings.

        Args:
            r2: Active radare2 session

        Returns:
            Success status

        """
        try:
            # Initialize ESIL VM
            r2._execute_command("aeim")

            # Set up stack
            r2._execute_command("aers 1024")  # Set stack size

            # Configure ESIL settings for analysis
            r2._execute_command("e esil.stack.addr=0x100000")
            r2._execute_command("e esil.stack.size=0x10000")
            r2._execute_command("e esil.debug=false")
            r2._execute_command("e esil.verbose=false")

            self.logger.info("ESIL VM initialized successfully")
            return True

        except R2Exception as e:
            self.logger.error(f"Failed to initialize ESIL VM: {e}")
            return False

    def emulate_function_execution(self, address: int, max_steps: int = 100) -> dict[str, Any]:
        """Emulate function execution using ESIL.

        Args:
            address: Function start address
            max_steps: Maximum execution steps

        Returns:
            Comprehensive emulation results

        """
        cache_key = f"{address}_{max_steps}"
        if cache_key in self.emulation_cache:
            return self.emulation_cache[cache_key]

        result = {
            "function_address": hex(address),
            "execution_trace": [],
            "register_states": [],
            "memory_accesses": [],
            "api_calls_detected": [],
            "branch_decisions": [],
            "final_state": {},
            "execution_time": 0,
            "steps_executed": 0,
            "vulnerabilities_detected": [],
            "license_checks_detected": [],
            "error": None,
        }

        start_time = time.time()

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Initialize ESIL VM
                if not self.initialize_esil_vm(r2):
                    result["error"] = "Failed to initialize ESIL VM"
                    return result

                # Set initial program counter
                r2._execute_command(f"s {hex(address)}")

                # Get initial register state
                initial_registers = r2.get_esil_registers()
                result["register_states"].append(
                    {
                        "step": 0,
                        "address": hex(address),
                        "registers": initial_registers,
                    },
                )

                # Perform step-by-step emulation
                for step in range(max_steps):
                    try:
                        # Execute one ESIL instruction
                        esil_output = r2._execute_command("aes")

                        if current_pc := r2._execute_command("dr?PC"):
                            current_pc = current_pc.strip()

                            # Get instruction at current PC
                            instruction = r2._execute_command(f"pd 1 @ {current_pc}")

                            # Record execution trace
                            trace_entry = {
                                "step": step + 1,
                                "address": current_pc,
                                "instruction": instruction.strip() if instruction else "",
                                "esil_output": esil_output.strip() if esil_output else "",
                            }
                            result["execution_trace"].append(trace_entry)

                            # Analyze instruction for patterns
                            self._analyze_instruction_patterns(trace_entry, result)

                            # Get register state periodically
                            if step % 10 == 0 or step < 5:
                                registers = r2.get_esil_registers()
                                result["register_states"].append(
                                    {
                                        "step": step + 1,
                                        "address": current_pc,
                                        "registers": registers,
                                    },
                                )

                            # Check for function exit conditions
                            if self._is_function_exit(instruction):
                                self.logger.info(f"Function exit detected at step {step + 1}")
                                break

                    except R2Exception as e:
                        self.logger.debug(f"ESIL execution error at step {step}: {e}")
                        if step == 0:  # If first step fails, it's a critical error
                            result["error"] = f"ESIL execution failed: {e}"
                            return result
                        break

                # Get final state
                result["final_state"] = {
                    "registers": r2.get_esil_registers(),
                    "stack_pointer": r2._execute_command("dr?SP"),
                    "program_counter": r2._execute_command("dr?PC"),
                }

                result["steps_executed"] = min(step + 1, max_steps)
                result["execution_time"] = time.time() - start_time

                # Perform post-execution analysis
                self._perform_post_execution_analysis(result)

                # Cache the result
                self.emulation_cache[cache_key] = result

        except R2Exception as e:
            result["error"] = str(e)
            self.logger.error(f"ESIL emulation failed for {hex(address)}: {e}")

        return result

    def _analyze_instruction_patterns(
        self, trace_entry: dict[str, Any], result: dict[str, Any]
    ) -> None:
        """Analyze individual instruction for interesting patterns."""
        instruction = trace_entry.get("instruction", "").lower()
        address = trace_entry.get("address", "")

        # Detect API calls
        if "call" in instruction and "0x" in instruction:
            target = instruction.split("0x")[1].split()[0]
            result["api_calls_detected"].append(
                {
                    "step": trace_entry["step"],
                    "caller_address": address,
                    "target_address": f"0x{target}",
                    "instruction": instruction,
                },
            )

        # Detect conditional branches
        if any(
            branch in instruction for branch in ["je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle"]
        ):
            result["branch_decisions"].append(
                {
                    "step": trace_entry["step"],
                    "address": address,
                    "instruction": instruction,
                    "branch_type": self._extract_branch_type(instruction),
                },
            )

        # Detect memory access patterns
        if any(op in instruction for op in ["mov", "lea", "push", "pop"]) and ("[" in instruction and "]" in instruction):
            result["memory_accesses"].append(
                {
                    "step": trace_entry["step"],
                    "address": address,
                    "instruction": instruction,
                    "access_type": self._extract_memory_access_type(instruction),
                },
            )

        # Detect license check patterns
        license_indicators = ["cmp", "test", "xor"]
        if any(indicator in instruction for indicator in license_indicators) and any(keyword in instruction for keyword in ["key", "serial", "license"]):
            result["license_checks_detected"].append(
                {
                    "step": trace_entry["step"],
                    "address": address,
                    "instruction": instruction,
                    "pattern_type": "license_comparison",
                },
            )

        # Detect vulnerability patterns
        vuln_indicators = ["strcpy", "strcat", "sprintf", "gets"]
        if any(indicator in instruction for indicator in vuln_indicators):
            result["vulnerabilities_detected"].append(
                {
                    "step": trace_entry["step"],
                    "address": address,
                    "instruction": instruction,
                    "vulnerability_type": "buffer_overflow_risk",
                },
            )

    def _extract_branch_type(self, instruction: str) -> str:
        """Extract branch type from instruction."""
        if "je" in instruction or "jz" in instruction:
            return "jump_if_equal"
        if "jne" in instruction or "jnz" in instruction:
            return "jump_if_not_equal"
        if "jg" in instruction:
            return "jump_if_greater"
        if "jl" in instruction:
            return "jump_if_less"
        if "jge" in instruction:
            return "jump_if_greater_equal"
        return "jump_if_less_equal" if "jle" in instruction else "unknown"

    def _extract_memory_access_type(self, instruction: str) -> str:
        """Extract memory access type from instruction."""
        if "mov" in instruction:
            return "move"
        if "lea" in instruction:
            return "load_effective_address"
        if "push" in instruction:
            return "stack_push"
        return "stack_pop" if "pop" in instruction else "unknown"

    def _is_function_exit(self, instruction: str) -> bool:
        """Check if instruction indicates function exit."""
        if not instruction:
            return False

        instruction_lower = instruction.lower()
        return any(exit_pattern in instruction_lower for exit_pattern in ["ret", "retn", "iret"])

    def _perform_post_execution_analysis(self, result: dict[str, Any]) -> None:
        """Perform analysis on the complete execution trace."""
        trace = result.get("execution_trace", [])

        # Analyze execution patterns
        self._analyze_execution_patterns(result, trace)

        # Detect license validation routines
        self._detect_license_validation_patterns(result, trace)

        # Analyze API call sequences
        self._analyze_api_call_sequences(result)

        # Detect anti-analysis techniques
        self._detect_anti_analysis_techniques(result, trace)

    def _analyze_execution_patterns(
        self, result: dict[str, Any], trace: list[dict[str, Any]]
    ) -> None:
        """Analyze overall execution patterns."""
        if not trace:
            return

        # Calculate basic metrics
        total_instructions = len(trace)
        unique_addresses = len({entry.get("address", "") for entry in trace})

        # Detect loops
        address_counts = {}
        for entry in trace:
            if addr := entry.get("address", ""):
                address_counts[addr] = address_counts.get(addr, 0) + 1

        loops_detected = sum(bool(count > 1)
                         for count in address_counts.values())

        result["execution_patterns"] = {
            "total_instructions_executed": total_instructions,
            "unique_addresses_visited": unique_addresses,
            "loops_detected": loops_detected,
            "code_coverage_ratio": unique_addresses / total_instructions
            if total_instructions > 0
            else 0,
        }

    def _detect_license_validation_patterns(
        self, result: dict[str, Any], trace: list[dict[str, Any]]
    ) -> None:
        """Detect license validation patterns in execution trace."""
        validation_patterns = []

        # Look for sequences that suggest license validation
        for i, entry in enumerate(trace):
            instruction = entry.get("instruction", "").lower()

            # Pattern 1: String comparison followed by conditional jump
            if "cmp" in instruction and i + 1 < len(trace):
                next_instruction = trace[i + 1].get("instruction", "").lower()
                if any(jump in next_instruction for jump in ["je", "jne", "jz", "jnz"]):
                    validation_patterns.append(
                        {
                            "type": "string_comparison_validation",
                            "start_step": entry["step"],
                            "end_step": trace[i + 1]["step"],
                            "instructions": [entry["instruction"], trace[i + 1]["instruction"]],
                        },
                    )

            # Pattern 2: Multiple comparisons (complex validation)
            if "cmp" in instruction:
                comparison_count = 1 + sum(bool("cmp" in trace[j].get("instruction", "").lower())
                                       for j in range(i + 1, min(i + 10, len(trace))))
                if comparison_count >= 3:
                    validation_patterns.append(
                        {
                            "type": "complex_validation_routine",
                            "start_step": entry["step"],
                            "comparison_count": comparison_count,
                            "pattern_strength": "high",
                        },
                    )

        result["license_validation_patterns"] = validation_patterns

    def _analyze_api_call_sequences(self, result: dict[str, Any]) -> None:
        """Analyze sequences of API calls for patterns."""
        api_calls = result.get("api_calls_detected", [])

        if not api_calls:
            return

        # Group consecutive API calls
        call_sequences = []
        current_sequence = []

        for call in api_calls:
            if not current_sequence or call["step"] - current_sequence[-1]["step"] <= 5:
                current_sequence.append(call)
            else:
                if len(current_sequence) > 1:
                    call_sequences.append(current_sequence)
                current_sequence = [call]

        if len(current_sequence) > 1:
            call_sequences.append(current_sequence)

        result["api_call_sequences"] = call_sequences

    def _detect_anti_analysis_techniques(
        self, result: dict[str, Any], trace: list[dict[str, Any]]
    ) -> None:
        """Detect anti-analysis and anti-debugging techniques."""
        anti_analysis_detected = []

        for entry in trace:
            instruction = entry.get("instruction", "").lower()

            # Detect debugger checks
            if any(
                pattern in instruction for pattern in ["isdebuggerpresent", "checkremotedebugger"]
            ):
                anti_analysis_detected.append(
                    {
                        "type": "debugger_detection",
                        "step": entry["step"],
                        "instruction": instruction,
                        "severity": "high",
                    },
                )

            # Detect timing checks
            if "rdtsc" in instruction:
                anti_analysis_detected.append(
                    {
                        "type": "timing_check",
                        "step": entry["step"],
                        "instruction": instruction,
                        "severity": "medium",
                    },
                )

            # Detect VM detection
            if any(pattern in instruction for pattern in ["cpuid", "in ", "out "]):
                anti_analysis_detected.append(
                    {
                        "type": "vm_detection",
                        "step": entry["step"],
                        "instruction": instruction,
                        "severity": "medium",
                    },
                )

        result["anti_analysis_techniques"] = anti_analysis_detected

    def emulate_multiple_functions(
        self, function_addresses: list[int], max_steps_per_function: int = 50
    ) -> dict[str, Any]:
        """Emulate multiple functions and provide comparative analysis.

        Args:
            function_addresses: List of function addresses to emulate
            max_steps_per_function: Maximum steps per function

        Returns:
            Comparative emulation results

        """
        results = {
            "emulation_summary": {
                "functions_emulated": len(function_addresses),
                "total_steps_executed": 0,
                "total_api_calls": 0,
                "total_license_checks": 0,
                "total_vulnerabilities": 0,
            },
            "function_results": {},
            "comparative_analysis": {},
        }

        for i, address in enumerate(function_addresses):
            self.logger.info(
                f"Emulating function {i + 1}/{len(function_addresses)}: {hex(address)}"
            )

            func_result = self.emulate_function_execution(address, max_steps_per_function)
            results["function_results"][hex(address)] = func_result

            # Update summary statistics
            if "error" not in func_result:
                results["emulation_summary"]["total_steps_executed"] += func_result.get(
                    "steps_executed", 0
                )
                results["emulation_summary"]["total_api_calls"] += len(
                    func_result.get("api_calls_detected", [])
                )
                results["emulation_summary"]["total_license_checks"] += len(
                    func_result.get("license_checks_detected", [])
                )
                results["emulation_summary"]["total_vulnerabilities"] += len(
                    func_result.get("vulnerabilities_detected", [])
                )

        # Perform comparative analysis
        results["comparative_analysis"] = self._perform_comparative_analysis(
            results["function_results"]
        )

        return results

    def _perform_comparative_analysis(self, function_results: dict[str, Any]) -> dict[str, Any]:
        """Perform comparative analysis across multiple function emulations."""
        analysis = {
            "most_complex_function": None,
            "most_api_calls": None,
            "most_license_checks": None,
            "common_patterns": [],
            "suspicious_functions": [],
        }

        max_steps = 0
        max_api_calls = 0
        max_license_checks = 0

        for addr, result in function_results.items():
            if "error" in result:
                continue

            steps = result.get("steps_executed", 0)
            api_calls = len(result.get("api_calls_detected", []))
            license_checks = len(result.get("license_checks_detected", []))

            # Track maximums
            if steps > max_steps:
                max_steps = steps
                analysis["most_complex_function"] = addr

            if api_calls > max_api_calls:
                max_api_calls = api_calls
                analysis["most_api_calls"] = addr

            if license_checks > max_license_checks:
                max_license_checks = license_checks
                analysis["most_license_checks"] = addr

            # Identify suspicious functions
            if license_checks > 0 or len(result.get("anti_analysis_techniques", [])) > 0:
                analysis["suspicious_functions"].append(
                    {
                        "address": addr,
                        "license_checks": license_checks,
                        "anti_analysis_techniques": len(result.get("anti_analysis_techniques", [])),
                        "suspicion_score": license_checks * 2
                        + len(result.get("anti_analysis_techniques", [])),
                    },
                )

        return analysis


def analyze_binary_esil(
    binary_path: str,
    radare2_path: str | None = None,
    function_limit: int = 10,
    max_steps: int = 100,
) -> dict[str, Any]:
    """Perform comprehensive ESIL analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        function_limit: Maximum number of functions to analyze
        max_steps: Maximum steps per function emulation

    Returns:
        Complete ESIL analysis results

    """
    engine = ESILAnalysisEngine(binary_path, radare2_path)

    # Get function addresses
    try:
        with r2_session(binary_path, radare2_path) as r2:
            functions = r2.get_functions()
            addresses = [f["offset"] for f in functions[:function_limit] if f.get("offset")]
    except R2Exception as e:
        logger.error("R2Exception in radare2_esil: %s", e)
        return {"error": f"Failed to get function list: {e}"}

    if not addresses:
        return {"error": "No functions found for analysis"}

    return engine.emulate_multiple_functions(addresses, max_steps)


__all__ = ["ESILAnalysisEngine", "analyze_binary_esil"]
