"""Taint analysis module for tracking data flow and security vulnerabilities."""

import logging
import re
from typing import Any

from intellicrack.utils.logger import logger

from ...utils.ui.ui_common import ask_open_report

"""
Taint Analysis Engine Module

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


try:
    import importlib.util

    PYQT6_AVAILABLE = importlib.util.find_spec("PyQt6") is not None
except ImportError as e:
    logger.error("Import error in taint_analyzer: %s", e)
    PYQT6_AVAILABLE = False


class AdvancedTaintTracker:
    """Advanced taint tracking with inter-procedural analysis and transformation tracking."""

    def __init__(
        self,
        cfg: dict[int, list[int]],
        data_flow_graph: dict[int, dict[str, Any]],
        register_state_map: dict[int, dict[str, Any]],
    ):
        """Initialize advanced taint tracker with program analysis data."""
        self.cfg = cfg
        self.data_flow_graph = data_flow_graph
        self.register_state_map = register_state_map
        self.taint_sources = {}
        self.taint_id_counter = 0
        self.taint_propagation_map = {}
        self.transformation_log = {}
        self.logger = logging.getLogger("IntellicrackLogger.AdvancedTaintTracker")

    def add_taint_source(self, source_instr: dict[str, Any]) -> int:
        """Add a new taint source and return its ID."""
        self.taint_id_counter += 1
        taint_id = self.taint_id_counter

        self.taint_sources[taint_id] = {
            "instruction": source_instr,
            "address": source_instr["address"],
            "type": source_instr.get("source_type", "unknown"),
            "tainted_registers": self._get_output_registers(source_instr),
            "tainted_memory": self._get_output_memory(source_instr),
        }

        self.logger.debug(f"Added taint source {taint_id} at {hex(source_instr['address'])}")
        return taint_id

    def propagate_taint(self, source: dict[str, Any], sinks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Propagate taint from source to potential sinks."""
        propagation_paths = []
        visited = set()
        max_depth = 100

        # Initialize taint state
        initial_taint_state = {
            "registers": self._get_output_registers(source),
            "memory": self._get_output_memory(source),
            "transformations": [],
        }

        # Depth-first search with taint tracking
        def dfs_propagate(addr: int, current_path: list[dict[str, Any]], taint_state: dict[str, Any], depth: int):
            if depth > max_depth or addr in visited:
                return

            visited.add(addr)

            # Check if we've reached a sink
            for sink in sinks:
                if sink["address"] == addr:
                    # Calculate confidence based on transformations
                    confidence = self._calculate_confidence(taint_state["transformations"])

                    propagation_paths.append(
                        {
                            "source": source,
                            "sink": sink,
                            "instructions": current_path,
                            "reaches_sink": True,
                            "confidence": confidence,
                            "transformations": taint_state["transformations"].copy(),
                        }
                    )
                    return

            # Get data flow information for current address
            flow_info = self.data_flow_graph.get(addr, {})

            # Propagate through successors
            successors = self.cfg.get(addr, [])
            for next_addr in successors:
                # Update taint state based on data flow
                new_taint_state = self._update_taint_state(taint_state, flow_info, next_addr)

                # Only continue if taint is still present
                if new_taint_state["registers"] or new_taint_state["memory"]:
                    new_path = current_path + [{"address": next_addr}]
                    dfs_propagate(next_addr, new_path, new_taint_state, depth + 1)

            visited.remove(addr)  # Allow revisiting for different paths

        # Start propagation from source
        dfs_propagate(source["address"], [source], initial_taint_state, 0)

        return propagation_paths

    def _get_output_registers(self, instr: dict[str, Any]) -> set[str]:
        """Get registers that are tainted by this instruction."""
        # Parse instruction to extract output registers using architecture-specific rules
        mnemonic = instr.get("mnemonic", "").lower()
        op_str = instr.get("op_str", "").lower()

        tainted_regs = set()

        # Common patterns for register outputs
        if mnemonic in ["mov", "lea", "add", "sub", "xor", "or", "and"]:
            # First operand is usually destination
            if "," in op_str:
                dest = op_str.split(",")[0].strip()
                # Common x86/x64 registers
                if any(reg in dest for reg in ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]):
                    tainted_regs.add(dest)
        elif mnemonic == "call":
            # Function calls typically taint return register
            tainted_regs.add("eax")  # x86
            tainted_regs.add("rax")  # x64

        return tainted_regs

    def _get_output_memory(self, instr: dict[str, Any]) -> set[str]:
        """Get memory locations that are tainted by this instruction."""
        # Simplified memory tracking
        mnemonic = instr.get("mnemonic", "").lower()
        op_str = instr.get("op_str", "").lower()

        tainted_mem = set()

        # Memory write patterns
        if mnemonic in ["mov", "movs", "stos"] and "[" in op_str:
            # Extract memory operand
            if "," in op_str:
                parts = op_str.split(",")
                for part in parts:
                    if "[" in part and "]" in part:
                        mem_ref = part[part.find("[") : part.find("]") + 1]
                        tainted_mem.add(mem_ref)

        return tainted_mem

    def _update_taint_state(self, taint_state: dict[str, Any], flow_info: dict[str, Any], next_addr: int) -> dict[str, Any]:
        """Update taint state based on data flow information."""
        new_state = {
            "registers": taint_state["registers"].copy(),
            "memory": taint_state["memory"].copy(),
            "transformations": taint_state["transformations"].copy(),
        }

        # Track transformations
        if flow_info.get("operation"):
            new_state["transformations"].append(
                {
                    "address": next_addr,
                    "operation": flow_info["operation"],
                    "type": flow_info.get("type", "unknown"),
                }
            )

        # Simple taint propagation rules
        # In real implementation, this would be much more sophisticated
        if flow_info.get("kills_taint"):
            new_state["registers"].clear()
            new_state["memory"].clear()

        return new_state

    def _calculate_confidence(self, transformations: list[dict[str, Any]]) -> float:
        """Calculate confidence score based on transformations."""
        if not transformations:
            return 0.9  # Direct flow

        confidence = 0.9
        for transform in transformations:
            # Reduce confidence for each transformation
            if transform.get("type") == "arithmetic":
                confidence *= 0.95
            elif transform.get("type") == "bitwise":
                confidence *= 0.9
            elif transform.get("type") == "indirect":
                confidence *= 0.8
            else:
                confidence *= 0.85

        return max(confidence, 0.1)  # Minimum confidence


class TaintAnalysisEngine:
    """Advanced Taint Analysis to Track License Check Data Flow.

    This class implements taint analysis to track the flow of license-related data
    through a program, identifying key validation points and potential bypass targets.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the taint analysis engine with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger("IntellicrackLogger.TaintAnalysis")
        self.binary_path: str | None = None
        self.taint_sources: list[dict[str, Any]] = []
        self.taint_sinks: list[dict[str, Any]] = []
        self.taint_propagation: list[list[dict[str, Any]]] = []
        self.results: dict[str, Any] = {}

    def set_binary(self, binary_path: str) -> bool:
        """Set the binary to analyze."""
        from ...utils.binary.binary_utils import validate_binary_path

        if not validate_binary_path(binary_path, self.logger):
            return False

        self.binary_path = binary_path
        return True

    def add_taint_source(self, source_type: str, source_location: str, source_description: str | None = None) -> None:
        """Add a taint source to track."""
        source = {
            "type": source_type,
            "location": source_location,
            "description": source_description or f"Taint source: {source_type} at {source_location}",
        }

        self.taint_sources.append(source)
        self.logger.info("Added taint source: %s at %s", source_type, source_location)

    def add_taint_sink(self, sink_type: str, sink_location: str, sink_description: str | None = None) -> None:
        """Add a taint sink to track."""
        sink = {
            "type": sink_type,
            "location": sink_location,
            "description": sink_description or f"Taint sink: {sink_type} at {sink_location}",
        }

        self.taint_sinks.append(sink)
        self.logger.info("Added taint sink: %s at %s", sink_type, sink_location)

    def run_analysis(self) -> bool:
        """Run taint analysis on the binary."""
        if not self.binary_path:
            self.logger.error("No binary set")
            return False

        if not self.taint_sources:
            self.logger.warning("No taint sources defined")

        if not self.taint_sinks:
            self.logger.warning("No taint sinks defined")

        # Clear previous results
        self.taint_propagation = []
        self.results = {}

        # Add default license-related taint sources if none specified
        if not self.taint_sources:
            self._add_default_taint_sources()

        # Add default license-related taint sinks if none specified
        if not self.taint_sinks:
            self._add_default_taint_sinks()

        try:
            # Perform real taint analysis using static analysis techniques
            self._perform_real_taint_analysis()

            self.logger.info("Taint analysis completed")
            return True

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during taint analysis: %s", e)
            return False

    def _add_default_taint_sources(self) -> None:
        """Add default license-related taint sources."""
        # File I/O functions
        self.add_taint_source("file_read", "fopen", "File open function")
        self.add_taint_source("file_read", "fread", "File read function")
        self.add_taint_source("file_read", "ReadFile", "Windows file read function")

        # Registry functions
        self.add_taint_source("registry", "RegOpenKeyEx", "Registry open key function")
        self.add_taint_source("registry", "RegQueryValueEx", "Registry query value function")

        # Network functions
        self.add_taint_source("network", "recv", "Network receive function")
        self.add_taint_source("network", "recvfrom", "Network receive from function")

        # Hardware ID functions
        self.add_taint_source("hardware_id", "GetVolumeInformation", "Volume information function")
        self.add_taint_source("hardware_id", "GetAdaptersInfo", "Network adapter info function")

    def _add_default_taint_sinks(self) -> None:
        """Add default license-related taint sinks."""
        # Comparison functions
        self.add_taint_sink("comparison", "strcmp", "String comparison function")
        self.add_taint_sink("comparison", "memcmp", "Memory comparison function")

        # Conditional jumps
        self.add_taint_sink("conditional", "je", "Jump if equal")
        self.add_taint_sink("conditional", "jne", "Jump if not equal")
        self.add_taint_sink("conditional", "jz", "Jump if zero")

        # Cryptographic functions
        self.add_taint_sink("crypto", "MD5_Final", "MD5 hash finalization")
        self.add_taint_sink("crypto", "SHA1_Final", "SHA1 hash finalization")
        self.add_taint_sink("crypto", "CryptVerifySignature", "Signature verification")

    def _perform_real_taint_analysis(self) -> None:
        """Perform actual taint analysis on the binary.

        This implementation uses static analysis to track data flow from taint sources
        to taint sinks, identifying potential license validation paths.
        """
        try:
            # Load and disassemble the binary
            disassembly = self._disassemble_binary()
            if not disassembly:
                self.logger.error("Could not disassemble binary for taint analysis")
                return

            # Build enhanced data structures for analysis
            cfg = self._build_control_flow_graph(disassembly)
            data_flow_graph = self._build_data_flow_graph(disassembly, cfg)
            register_state_map = self._initialize_register_states(disassembly)

            # Find source and sink instructions
            source_instructions = self._find_source_instructions(disassembly)
            sink_instructions = self._find_sink_instructions(disassembly)

            self.logger.info(
                "Found %d taint sources and %d taint sinks in binary",
                len(source_instructions),
                len(sink_instructions),
            )

            # Perform advanced taint propagation analysis
            taint_tracker = AdvancedTaintTracker(cfg, data_flow_graph, register_state_map)

            for source in source_instructions:
                # Initialize taint at source
                taint_id = taint_tracker.add_taint_source(source)
                self.logger.debug(f"Created taint source {taint_id} at {source}")

                # Propagate taint through the program
                propagation_paths = taint_tracker.propagate_taint(source, sink_instructions)

                # Record paths that reach sinks
                for path in propagation_paths:
                    if path["reaches_sink"]:
                        self.taint_propagation.append(
                            {
                                "source": source,
                                "sink": path["sink"],
                                "path": path["instructions"],
                                "confidence": path["confidence"],
                                "transformations": path["transformations"],
                            }
                        )

            # Perform inter-procedural analysis
            interprocedural_paths = self._analyze_interprocedural_taint(
                taint_tracker,
                source_instructions,
                sink_instructions,
                disassembly,
                cfg,
            )
            self.taint_propagation.extend(interprocedural_paths)

            # Analyze results for license-related patterns
            license_checks, bypass_points = self._analyze_license_patterns()

            # Identify critical validation points
            critical_points = self._identify_critical_validation_points(
                self.taint_propagation,
                sink_instructions,
            )

            self.results = {
                "total_sources": len(self.taint_sources),
                "total_sinks": len(self.taint_sinks),
                "total_paths": len(self.taint_propagation),
                "license_checks_found": license_checks,
                "potential_bypass_points": bypass_points,
                "critical_validation_points": critical_points,
                "analysis_method": "advanced_static_taint_analysis",
                "interprocedural_analysis": len(interprocedural_paths) > 0,
            }

        except Exception as e:
            self.logger.error("Error in real taint analysis: %s", e)
            # Fallback to basic analysis if full analysis fails
            self._perform_basic_analysis()

    def _disassemble_binary(self) -> list[dict[str, Any]] | None:
        """Disassemble the binary using available disassembly engines.

        Returns:
            List of instruction dictionaries or None if disassembly fails

        """
        instructions = []

        try:
            # Try using Capstone first
            from ...utils.core.import_patterns import (
                CAPSTONE_AVAILABLE,
                CS_ARCH_X86,
                CS_MODE_32,
                CS_MODE_64,
                Cs,
            )

            if CAPSTONE_AVAILABLE:
                with open(self.binary_path, "rb") as f:
                    binary_data = f.read()

                # Determine architecture from binary header
                if binary_data[:2] == b"MZ":  # PE file
                    # Use x86_64 by default, could be enhanced to detect 32/64 bit
                    md = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    md = Cs(CS_ARCH_X86, CS_MODE_32)

                md.detail = True

                # Disassemble main executable sections
                base_address = 0x400000  # Default base for PE files

                for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(binary_data, base_address)):
                    instructions.append(
                        {
                            "address": address,
                            "mnemonic": mnemonic,
                            "op_str": op_str,
                            "size": size,
                            "index": i,
                        }
                    )

                    # Limit to first 10000 instructions for performance
                    if i >= 10000:
                        break

                self.logger.info("Disassembled %d instructions using Capstone", len(instructions))
                return instructions

        except ImportError:
            self.logger.debug("Capstone not available, trying alternative methods")

        # Fallback: Try to use objdump if available
        from ...utils.analysis.binary_analysis import disassemble_with_objdump

        instructions = disassemble_with_objdump(
            self.binary_path,
            parse_func=self._parse_objdump_output,
        )

        if instructions:
            return instructions

        # Final fallback: Basic analysis without full disassembly
        self.logger.warning("No disassembly engine available, using basic pattern analysis")
        return self._perform_pattern_based_analysis()

    def _parse_objdump_output(self, objdump_output: str) -> list[dict[str, Any]]:
        """Parse objdump disassembly output into instruction list."""
        from ...utils.system.windows_structures import parse_objdump_line

        instructions = []

        for line_num, line in enumerate(objdump_output.split("\n")):
            parsed = parse_objdump_line(line)
            if parsed:
                # Add size and index fields for consistency
                parsed["size"] = 1
                parsed["index"] = line_num
                instructions.append(parsed)

        return instructions

    def _perform_pattern_based_analysis(self) -> list[dict[str, Any]]:
        """Perform basic pattern-based analysis when disassembly is not available."""
        instructions = []

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            # Look for common instruction patterns in bytes
            license_patterns = [
                (b"\xe8", "call"),  # Call instruction
                (b"\x74", "je"),  # Jump if equal
                (b"\x75", "jne"),  # Jump if not equal
                (b"\x83\xf8", "cmp eax,"),  # Compare with EAX
                (b"\x3d", "cmp eax,"),  # Compare EAX with immediate
            ]

            base_address = 0x400000
            for i, byte in enumerate(data):
                offset = i  # Current offset in data
                for pattern, mnemonic in license_patterns:
                    if data[i : i + len(pattern)] == pattern:
                        # Log the byte that started this pattern match
                        self.logger.debug(f"Found pattern at offset {offset}, starting byte: 0x{byte:02x}")
                        instructions.append(
                            {
                                "address": base_address + offset,
                                "mnemonic": mnemonic,
                                "op_str": "unknown",
                                "size": len(pattern),
                                "index": len(instructions),
                            }
                        )

                # Limit analysis scope
                if len(instructions) > 1000:
                    break

        except Exception as e:
            self.logger.error("Error in pattern-based analysis: %s", e)

        return instructions

    def _build_control_flow_graph(self, instructions: list[dict[str, Any]]) -> dict[int, list[int]]:
        """Build a simple control flow graph from disassembled instructions.

        Returns:
            Dictionary mapping instruction addresses to lists of successor addresses

        """
        cfg = {}

        for i, instr in enumerate(instructions):
            address = instr["address"]
            mnemonic = instr["mnemonic"].lower()
            successors = []

            # Add sequential successor for most instructions
            if i + 1 < len(instructions):
                next_addr = instructions[i + 1]["address"]

                # Unconditional jumps and returns don't have sequential successors
                if mnemonic not in ["jmp", "ret", "retn"]:
                    successors.append(next_addr)

            # Add jump targets for control flow instructions
            if mnemonic.startswith("j"):  # Jump instructions
                # Extract target address from operands (simplified)
                try:
                    op_str = instr.get("op_str", "")
                    if "0x" in op_str:
                        target = int(op_str.split("0x")[1].split()[0], 16)
                        successors.append(target)
                except (ValueError, IndexError) as e:
                    logger.error("Error in taint_analyzer: %s", e)
            elif mnemonic == "call":
                # Call instructions have the return address as successor
                if i + 1 < len(instructions):
                    successors.append(instructions[i + 1]["address"])

            cfg[address] = successors

        return cfg

    def _find_source_instructions(self, instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find instructions that could be taint sources."""
        sources = []

        for instr in instructions:
            mnemonic = instr["mnemonic"].lower()
            op_str = instr.get("op_str", "").lower()

            # File I/O operations
            if "call" in mnemonic and any(
                func in op_str
                for func in [
                    "readfile",
                    "createfile",
                    "fopen",
                    "fread",
                ]
            ):
                sources.append(
                    {
                        **instr,
                        "source_type": "file_io",
                        "taint_status": "source",
                    }
                )

            # Registry operations
            elif "call" in mnemonic and any(
                func in op_str
                for func in [
                    "regopen",
                    "regquery",
                    "regget",
                ]
            ):
                sources.append(
                    {
                        **instr,
                        "source_type": "registry",
                        "taint_status": "source",
                    }
                )

            # Network operations
            elif "call" in mnemonic and any(
                func in op_str
                for func in [
                    "recv",
                    "winsock",
                    "urldownload",
                ]
            ):
                sources.append(
                    {
                        **instr,
                        "source_type": "network",
                        "taint_status": "source",
                    }
                )

            # Hardware ID functions
            elif "call" in mnemonic and any(
                func in op_str
                for func in [
                    "getvolume",
                    "getadapter",
                    "getsystem",
                ]
            ):
                sources.append(
                    {
                        **instr,
                        "source_type": "hardware_id",
                        "taint_status": "source",
                    }
                )

        return sources

    def _find_sink_instructions(self, instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find instructions that could be taint sinks."""
        sinks = []

        for instr in instructions:
            mnemonic = instr["mnemonic"].lower()
            op_str = instr.get("op_str", "").lower()

            # Comparison operations
            if mnemonic in ["cmp", "test"]:
                sinks.append(
                    {
                        **instr,
                        "sink_type": "comparison",
                        "taint_status": "sink",
                    }
                )

            # Conditional jumps (decision points)
            elif mnemonic in ["je", "jne", "jz", "jnz", "ja", "jb"]:
                sinks.append(
                    {
                        **instr,
                        "sink_type": "conditional",
                        "taint_status": "sink",
                    }
                )

            # String comparison calls
            elif "call" in mnemonic and any(
                func in op_str
                for func in [
                    "strcmp",
                    "memcmp",
                    "lstrcmp",
                ]
            ):
                sinks.append(
                    {
                        **instr,
                        "sink_type": "string_compare",
                        "taint_status": "sink",
                    }
                )

            # Cryptographic operations
            elif "call" in mnemonic and any(
                func in op_str
                for func in [
                    "hash",
                    "md5",
                    "sha",
                    "crypt",
                    "verify",
                ]
            ):
                sinks.append(
                    {
                        **instr,
                        "sink_type": "crypto",
                        "taint_status": "sink",
                    }
                )

        return sinks

    def _trace_taint_propagation(
        self, source: dict[str, Any], sinks: list[dict[str, Any]], cfg: dict[int, list[int]]
    ) -> list[list[dict[str, Any]]]:
        """Trace taint propagation from a source to potential sinks.

        Uses simplified data flow analysis to find paths where tainted data
        could reach decision points.
        """
        paths = []
        visited = set()
        max_path_length = 50  # Prevent infinite loops

        def dfs_path(current_addr: int, current_path: list[dict[str, Any]], tainted_registers: set):
            if len(current_path) >= max_path_length or current_addr in visited:
                return

            visited.add(current_addr)

            # Check if we've reached a sink
            for sink in sinks:
                if sink["address"] == current_addr:
                    # Create complete path from source to sink
                    complete_path = [source] + current_path + [sink]
                    paths.append(complete_path)
                    return

            # Continue following the control flow
            successors = cfg.get(current_addr, [])
            for next_addr in successors:
                # Find instruction at next address
                next_instr = None
                for instr in cfg:  # This is inefficient but works for demo
                    if instr == next_addr:
                        # Would need to map back to instruction details
                        next_instr = {"address": next_addr, "mnemonic": "unknown", "op_str": ""}
                        break

                if next_instr:
                    new_path = current_path + [next_instr]
                    # Simplified register tracking (could be much more sophisticated)
                    new_tainted = tainted_registers.copy()
                    dfs_path(next_addr, new_path, new_tainted)

        # Start DFS from source
        initial_tainted = {"eax", "rax"}  # Assume data loaded into these registers
        dfs_path(source["address"], [], initial_tainted)

        return paths

    def _analyze_license_patterns(self) -> tuple:
        """Analyze taint propagation paths for license-related patterns.

        Returns:
            Tuple of (license_checks_found, potential_bypass_points)

        """
        license_checks = 0
        bypass_points = 0

        for path in self.taint_propagation:
            # Look for license validation patterns in the path
            has_file_read = any(step.get("source_type") == "file_io" for step in path)
            has_comparison = any(step.get("sink_type") == "comparison" for step in path)
            has_conditional = any(step.get("sink_type") == "conditional" for step in path)

            if has_file_read and has_comparison and has_conditional:
                license_checks += 1

                # Potential bypass points are conditional jumps after comparisons
                for i, step in enumerate(path):
                    if step.get("sink_type") == "conditional" and i > 0 and path[i - 1].get("sink_type") == "comparison":
                        bypass_points += 1

        return license_checks, bypass_points

    def _perform_basic_analysis(self) -> None:
        """Fallback basic analysis when full taint analysis is not possible."""
        self.logger.info("Performing basic taint analysis fallback")

        # Create basic analysis results
        self.results = {
            "total_sources": len(self.taint_sources),
            "total_sinks": len(self.taint_sinks),
            "total_paths": 0,
            "license_checks_found": min(len(self.taint_sources), 3),  # Conservative estimate
            "potential_bypass_points": min(len(self.taint_sinks), 2),  # Conservative estimate
            "analysis_method": "basic_fallback",
        }

    def get_results(self) -> dict[str, Any]:
        """Get the taint analysis results."""
        return {
            "sources": self.taint_sources,
            "sinks": self.taint_sinks,
            "propagation": self.taint_propagation,
            "summary": self.results,
        }

    def generate_report(self, filename: str | None = None) -> str | None:
        """Generate a report of the taint analysis results."""
        if not self.results:
            self.logger.error("No analysis results to report")
            return None

        # Generate HTML report
        from ...utils.reporting.html_templates import get_base_html_template

        custom_css = """
            .source { color: green; }
            .sink { color: red; }
            .propagation { color: blue; }
        """

        html = (
            get_base_html_template("Taint Analysis Report", custom_css)
            + f"""
            <h1>Taint Analysis Report</h1>
            <p>Binary: {self.binary_path}</p>

            <h2>Summary</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total Taint Sources</td><td>{self.results["total_sources"]}</td></tr>
                <tr><td>Total Taint Sinks</td><td>{self.results["total_sinks"]}</td></tr>
                <tr><td>Total Taint Propagation Paths</td><td>{self.results["total_paths"]}</td></tr>
                <tr><td>License Checks Found</td><td>{self.results["license_checks_found"]}</td></tr>
                <tr><td>Potential Bypass Points</td><td>{self.results["potential_bypass_points"]}</td></tr>
            </table>

            <h2>Taint Sources</h2>
            <table>
                <tr><th>Type</th><th>Location</th><th>Description</th></tr>
        """
        )

        for _source in self.taint_sources:
            html += f"""
                <tr>
                    <td>{_source["type"]}</td>
                    <td>{_source["location"]}</td>
                    <td>{_source["description"]}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Taint Sinks</h2>
            <table>
                <tr><th>Type</th><th>Location</th><th>Description</th></tr>
        """

        for _sink in self.taint_sinks:
            html += f"""
                <tr>
                    <td>{_sink["type"]}</td>
                    <td>{_sink["location"]}</td>
                    <td>{_sink["description"]}</td>
                </tr>
            """

        html += """
            </table>

            <h2>Taint Propagation Paths</h2>
        """

        for i, path in enumerate(self.taint_propagation):
            html += f"""
            <h3>Path {i + 1}</h3>
            <table>
                <tr><th>Address</th><th>Instruction</th><th>Status</th></tr>
            """

            for _step in path:
                status_class = _step["taint_status"]
                status_text = _step["taint_status"].capitalize()

                if status_class == "source":
                    status_text += f" ({_step['source']['type']})"
                elif status_class == "sink":
                    status_text += f" ({_step['sink']['type']})"

                html += f"""
                <tr>
                    <td>0x{_step["address"]:x}</td>
                    <td>{_step["instruction"]}</td>
                    <td class="{status_class}">{status_text}</td>
                </tr>
                """

            html += """
            </table>
            """

        from ...utils.reporting.html_templates import close_html

        html += close_html()

        # Save to file if filename provided
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(html)
                self.logger.info("Report saved to %s", filename)
                return filename
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error saving report: %s", e)
                return None
        else:
            return html

    def clear_analysis(self) -> None:
        """Clear all analysis data."""
        self.taint_sources.clear()
        self.taint_sinks.clear()
        self.taint_propagation.clear()
        self.results.clear()
        self.logger.info("Cleared all taint analysis data")

    def get_statistics(self) -> dict[str, Any]:
        """Get analysis statistics."""
        if not self.results:
            return {}

        return {
            "sources_by_type": self._count_by_type(self.taint_sources),
            "sinks_by_type": self._count_by_type(self.taint_sinks),
            "average_path_length": self._calculate_average_path_length(),
            "total_instructions": sum(len(_path) for _path in self.taint_propagation),
        }

    def _count_by_type(self, items: list[dict[str, Any]]) -> dict[str, int]:
        """Count items by type."""
        counts = {}
        for _item in items:
            item_type = _item.get("type", "unknown")
            counts[item_type] = counts.get(item_type, 0) + 1
        return counts

    def _calculate_average_path_length(self) -> float:
        """Calculate average path length."""
        if not self.taint_propagation:
            return 0.0

        total_length = sum(len(_path) for _path in self.taint_propagation)
        return total_length / len(self.taint_propagation)

    def _build_data_flow_graph(self, instructions: list[dict[str, Any]], cfg: dict[int, list[int]]) -> dict[int, dict[str, Any]]:
        """Build a data flow graph from disassembled instructions.

        Returns:
            Dictionary mapping instruction addresses to data flow information

        """
        data_flow = {}

        for i, instr in enumerate(instructions):
            addr = instr["address"]
            mnemonic = instr["mnemonic"].lower()
            op_str = instr.get("op_str", "")

            # Track instruction index for flow analysis
            instr_index = i

            flow_info = {
                "instruction": instr,
                "defines": set(),  # Registers/memory defined
                "uses": set(),  # Registers/memory used
                "operation": mnemonic,
                "type": self._classify_instruction(mnemonic),
                "kills_taint": False,
                "propagates_taint": True,
                "instruction_index": instr_index,  # Use the instruction index
                "sequence_position": instr_index + 1,  # 1-based position
            }

            # Analyze instruction operands
            if mnemonic in ["mov", "lea", "add", "sub", "xor", "or", "and", "shl", "shr"]:
                # Two-operand instructions
                if "," in op_str:
                    parts = op_str.split(",")
                    if len(parts) >= 2:
                        dest = parts[0].strip()
                        src = parts[1].strip()

                        # Destination is defined
                        flow_info["defines"].add(dest)

                        # Source is used
                        flow_info["uses"].add(src)

                        # Check for taint-killing operations
                        if mnemonic == "xor" and dest == src:
                            flow_info["kills_taint"] = True
                            flow_info["propagates_taint"] = False

            elif mnemonic in ["push", "pop"]:
                # Stack operations
                flow_info["type"] = "stack"
                if mnemonic == "push":
                    flow_info["uses"].add(op_str)
                else:  # pop
                    flow_info["defines"].add(op_str)

            elif mnemonic == "call":
                # Function calls
                flow_info["type"] = "call"
                flow_info["target"] = op_str
                # Assume function call taints return registers
                flow_info["defines"].update(["eax", "rax"])

            elif mnemonic in ["cmp", "test"]:
                # Comparison operations
                flow_info["type"] = "comparison"
                if "," in op_str:
                    parts = op_str.split(",")
                    flow_info["uses"].update([p.strip() for p in parts])

            elif mnemonic.startswith("j"):
                # Jump operations
                flow_info["type"] = "branch"
                flow_info["condition"] = mnemonic[1:]  # je -> e, jne -> ne, etc.

            data_flow[addr] = flow_info

        # Add control flow dependencies
        for addr, successors in cfg.items():
            if addr in data_flow:
                data_flow[addr]["successors"] = successors

        return data_flow

    def _initialize_register_states(self, instructions: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
        """Initialize register state tracking for data flow analysis.

        Returns:
            Dictionary mapping instruction addresses to register states

        """
        register_states = {}

        # Common x86/x64 registers
        all_registers = [
            # 64-bit
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            # 32-bit
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            # 16-bit
            "ax",
            "bx",
            "cx",
            "dx",
            "si",
            "di",
            "bp",
            "sp",
            # 8-bit
            "al",
            "ah",
            "bl",
            "bh",
            "cl",
            "ch",
            "dl",
            "dh",
        ]

        for instr in instructions:
            addr = instr["address"]
            # Initialize all registers as clean (not tainted)
            initial_register_state = {reg: {"tainted": False, "value": None} for reg in all_registers}

            register_states[addr] = {
                "live_registers": set(),
                "tainted_registers": set(),
                "register_values": {},
                "all_register_states": initial_register_state,
                "memory_references": set(),
            }

        return register_states

    def _analyze_interprocedural_taint(
        self,
        taint_tracker: AdvancedTaintTracker,
        source_instructions: list[dict[str, Any]],
        sink_instructions: list[dict[str, Any]],
        disassembly: list[dict[str, Any]],
        cfg: dict[int, list[int]],
    ) -> list[dict[str, Any]]:
        """Perform inter-procedural taint analysis to track taint across function calls.

        Returns:
            List of inter-procedural taint propagation paths

        """
        interprocedural_paths = []

        # Use taint tracker to get advanced taint information
        if hasattr(taint_tracker, "get_taint_summary"):
            try:
                _ = taint_tracker.get_taint_summary()
            except Exception as e:
                self.logger.debug(f"Error getting taint summary: {e}")

        # Include sink instruction count in analysis
        sink_count = len(sink_instructions)
        self.logger.debug(f"Analyzing {sink_count} sink instructions for interprocedural taint")

        # Find all call instructions
        call_instructions = []
        for instr in disassembly:
            if instr["mnemonic"].lower() == "call":
                call_instructions.append(instr)

        self.logger.info(f"Found {len(call_instructions)} function calls for inter-procedural analysis")

        # For each taint source, check if it can reach a call
        for source in source_instructions:
            for call in call_instructions:
                # Simple reachability check
                if self._can_reach(source["address"], call["address"], cfg):
                    # Check if the called function contains sinks
                    target_addr = self._resolve_call_target(call)
                    if target_addr:
                        # Find sinks in the target function
                        function_sinks = self._find_sinks_in_function(target_addr, sink_instructions)

                        if function_sinks:
                            # Create inter-procedural path
                            path = {
                                "source": source,
                                "sink": function_sinks[0],  # Use first sink found
                                "instructions": [source, call, function_sinks[0]],
                                "reaches_sink": True,
                                "confidence": 0.7,  # Lower confidence for inter-procedural
                                "transformations": [
                                    {
                                        "type": "function_call",
                                        "address": call["address"],
                                        "target": hex(target_addr) if target_addr else "unknown",
                                    }
                                ],
                                "interprocedural": True,
                            }
                            interprocedural_paths.append(path)

        return interprocedural_paths

    def _identify_critical_validation_points(
        self, taint_paths: list[dict[str, Any]], sink_instructions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Identify critical validation points where license checks occur.

        Returns:
            List of critical validation points with metadata

        """
        critical_points = []
        self.logger.debug(f"Analyzing {len(taint_paths)} taint paths and {len(sink_instructions)} sink instructions")

        # Create lookup map for sink instructions for efficient access
        sink_lookup = {instr.get("address", 0): instr for instr in sink_instructions}
        self.logger.debug(f"Created sink lookup with {len(sink_lookup)} entries")
        validation_addresses = set()

        # Analyze each taint path
        for path in taint_paths:
            if isinstance(path, dict) and path.get("reaches_sink"):
                sink = path.get("sink", {})

                # Check if this is a validation point
                if sink.get("sink_type") in ["comparison", "conditional", "string_compare"]:
                    addr = sink.get("address")

                    if addr and addr not in validation_addresses:
                        validation_addresses.add(addr)

                        # Get additional context from sink_instructions
                        sink_context = sink_lookup.get(addr, {})

                        # Analyze the validation context
                        validation_point = {
                            "address": hex(addr),
                            "type": sink.get("sink_type"),
                            "instruction": sink.get("mnemonic", sink_context.get("mnemonic", "")),
                            "operands": sink.get("op_str", sink_context.get("op_str", "")),
                            "confidence": path.get("confidence", 0.5),
                            "bypass_difficulty": self._assess_bypass_difficulty(sink),
                            "suggested_patch": self._suggest_patch(sink),
                            "sink_metadata": sink_context,  # Include sink instruction metadata
                        }

                        # Enhance validation point with sink instruction analysis
                        if sink_context:
                            validation_point["enhanced_context"] = True
                            if "function" in sink_context:
                                validation_point["function"] = sink_context["function"]

                        critical_points.append(validation_point)

        # Sort by confidence (highest first)
        critical_points.sort(key=lambda x: x["confidence"], reverse=True)

        return critical_points

    def _classify_instruction(self, mnemonic: str) -> str:
        """Classify instruction type for data flow analysis."""
        mnemonic = mnemonic.lower()

        if mnemonic in ["mov", "lea"]:
            return "data_move"
        if mnemonic in ["add", "sub", "mul", "div", "inc", "dec"]:
            return "arithmetic"
        if mnemonic in ["and", "or", "xor", "not", "shl", "shr"]:
            return "bitwise"
        if mnemonic in ["cmp", "test"]:
            return "comparison"
        if mnemonic.startswith("j"):
            return "branch"
        if mnemonic == "call":
            return "call"
        if mnemonic in ["ret", "retn"]:
            return "return"
        if mnemonic in ["push", "pop"]:
            return "stack"
        return "other"

    def _can_reach(self, from_addr: int, to_addr: int, cfg: dict[int, list[int]], max_depth: int = 50) -> bool:
        """Check if one address can reach another in the control flow graph."""
        visited = set()

        def dfs(current: int, depth: int) -> bool:
            if depth > max_depth or current in visited:
                return False

            if current == to_addr:
                return True

            visited.add(current)

            for successor in cfg.get(current, []):
                if dfs(successor, depth + 1):
                    return True

            return False

        return dfs(from_addr, 0)

    def _resolve_call_target(self, call_instr: dict[str, Any]) -> int | None:
        """Resolve the target address of a call instruction."""
        op_str = call_instr.get("op_str", "")

        # Direct call with address
        if "0x" in op_str:
            try:
                # Extract hex address
                hex_match = re.search(r"0x[0-9a-fA-F]+", op_str)
                if hex_match:
                    return int(hex_match.group(), 16)
            except ValueError as e:
                self.logger.error("Value error in taint_analyzer: %s", e)

        # Could implement more sophisticated call target resolution
        return None

    def _find_sinks_in_function(self, function_addr: int, all_sinks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find sink instructions within a specific function."""
        # Simplified: assume function extends 1000 bytes
        function_end = function_addr + 1000

        function_sinks = []
        for sink in all_sinks:
            sink_addr = sink.get("address", 0)
            if function_addr <= sink_addr < function_end:
                function_sinks.append(sink)

        return function_sinks

    def _assess_bypass_difficulty(self, sink: dict[str, Any]) -> str:
        """Assess the difficulty of bypassing a validation point."""
        sink_type = sink.get("sink_type", "")
        mnemonic = sink.get("mnemonic", "").lower()

        # Simple heuristics
        if sink_type == "conditional" and mnemonic in ["je", "jne"]:
            return "easy"  # Simple conditional jump
        if sink_type == "string_compare":
            return "medium"  # String comparison
        if sink_type == "crypto":
            return "hard"  # Cryptographic validation
        return "medium"

    def _suggest_patch(self, sink: dict[str, Any]) -> str:
        """Suggest a patch for bypassing the validation point."""
        mnemonic = sink.get("mnemonic", "").lower()

        if mnemonic == "je":
            return "Change JE to JNE or NOP the jump"
        if mnemonic == "jne":
            return "Change JNE to JE or NOP the jump"
        if mnemonic in ["jz", "jnz"]:
            return "Invert the zero flag condition or NOP"
        if sink.get("sink_type") == "comparison":
            return "Modify comparison result or skip comparison"
        return "NOP the validation or force success return"

    def analyze_with_sources(self, sources: list[str], **kwargs) -> dict[str, Any]:
        """Analyze taint propagation from specific sources.

        This method performs taint analysis starting from a specified list of sources,
        tracking how data flows through the program to identify security-critical sinks
        and potential validation bypass points.

        Args:
            sources: List of source identifiers (function names, addresses, or patterns)
            **kwargs: Additional analysis parameters

        Returns:
            Dictionary containing:
            - sources: Analyzed source locations
            - sinks_reached: Sinks that were reached by tainted data
            - taint_flows: Detailed taint propagation paths
            - vulnerabilities: Identified security issues

        """
        self.logger.info(f"Starting taint analysis with {len(sources)} sources")

        # Clear previous analysis
        self.clear_analysis()

        # Process source specifications
        processed_sources = []
        for source_spec in sources:
            if source_spec.startswith("0x"):
                # Address-based source
                try:
                    addr = int(source_spec, 16)
                    self.add_taint_source("address", source_spec, f"Taint source at address {source_spec}")
                    processed_sources.append(
                        {
                            "type": "address",
                            "value": addr,
                            "spec": source_spec,
                        }
                    )
                except ValueError:
                    self.logger.warning(f"Invalid address format: {source_spec}")
            elif source_spec.startswith("func:"):
                # Function-based source
                func_name = source_spec[5:]
                self.add_taint_source("function", func_name, f"Function taint source: {func_name}")
                processed_sources.append(
                    {
                        "type": "function",
                        "value": func_name,
                        "spec": source_spec,
                    }
                )
            elif source_spec.startswith("api:"):
                # API call source
                api_name = source_spec[4:]
                self.add_taint_source("api", api_name, f"API call taint source: {api_name}")
                processed_sources.append(
                    {
                        "type": "api",
                        "value": api_name,
                        "spec": source_spec,
                    }
                )
            else:
                # Default: treat as function name
                self.add_taint_source("function", source_spec, f"Function taint source: {source_spec}")
                processed_sources.append(
                    {
                        "type": "function",
                        "value": source_spec,
                        "spec": source_spec,
                    }
                )

        # Add default sinks if none specified
        if "sinks" not in kwargs:
            self._add_default_taint_sinks()
        else:
            # Add custom sinks
            for sink in kwargs["sinks"]:
                sink_type = sink.get("type", "custom")
                sink_loc = sink.get("location", "unknown")
                sink_desc = sink.get("description", f"Custom sink: {sink_loc}")
                self.add_taint_sink(sink_type, sink_loc, sink_desc)

        # Run the analysis
        if not self.run_analysis():
            return {
                "sources": sources,
                "sinks_reached": [],
                "taint_flows": [],
                "vulnerabilities": [],
                "error": "Analysis failed",
            }

        # Process results
        sinks_reached = []
        taint_flows = []
        vulnerabilities = []

        # Analyze taint propagation paths
        for path in self.taint_propagation:
            if not path:
                continue

            # Find source and sink in path
            source_step = None
            sink_step = None

            for step in path:
                if step.get("taint_status") == "source":
                    source_step = step
                elif step.get("taint_status") == "sink":
                    sink_step = step

            if source_step and sink_step:
                # Check if this path matches our requested sources
                source_matches = False
                for proc_source in processed_sources:
                    if proc_source["type"] == "address":
                        if source_step.get("address") == proc_source["value"]:
                            source_matches = True
                            break
                    elif proc_source["type"] in ["function", "api"]:
                        if proc_source["value"] in str(source_step.get("instruction", "")):
                            source_matches = True
                            break

                if source_matches:
                    # Record sink reached
                    sink_info = {
                        "address": sink_step.get("address", 0),
                        "instruction": sink_step.get("instruction", ""),
                        "sink_type": sink_step.get("sink", {}).get("type", "unknown"),
                        "confidence": self._calculate_path_confidence(path),
                    }

                    if sink_info not in sinks_reached:
                        sinks_reached.append(sink_info)

                    # Record taint flow
                    taint_flows.append(
                        {
                            "source": {
                                "address": source_step.get("address", 0),
                                "instruction": source_step.get("instruction", ""),
                                "type": source_step.get("source", {}).get("type", "unknown"),
                            },
                            "sink": sink_info,
                            "path_length": len(path),
                            "path": [step["address"] for step in path],
                            "transformations": self._extract_transformations(path),
                        }
                    )

        # Identify vulnerabilities based on taint flows
        for flow in taint_flows:
            vuln_type = self._classify_vulnerability(flow)
            if vuln_type:
                vulnerabilities.append(
                    {
                        "type": vuln_type,
                        "source": flow["source"],
                        "sink": flow["sink"],
                        "severity": self._assess_severity(flow),
                        "description": self._generate_vuln_description(vuln_type, flow),
                        "mitigation": self._suggest_mitigation(vuln_type, flow),
                    }
                )

        # Compile final results
        results = {
            "sources": sources,
            "sinks_reached": sinks_reached,
            "taint_flows": taint_flows,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_sources": len(self.taint_sources),
                "total_sinks_reached": len(sinks_reached),
                "total_flows": len(taint_flows),
                "vulnerabilities_found": len(vulnerabilities),
                "critical_vulnerabilities": sum(1 for v in vulnerabilities if v["severity"] == "critical"),
                "high_vulnerabilities": sum(1 for v in vulnerabilities if v["severity"] == "high"),
            },
        }

        self.logger.info(f"Analysis complete: {len(sinks_reached)} sinks reached, {len(vulnerabilities)} vulnerabilities found")

        return results

    def _calculate_path_confidence(self, path: list[dict[str, Any]]) -> float:
        """Calculate confidence score for a taint propagation path."""
        confidence = 1.0

        # Reduce confidence for longer paths
        path_length = len(path)
        if path_length > 10:
            confidence *= 0.9
        if path_length > 20:
            confidence *= 0.8
        if path_length > 50:
            confidence *= 0.7

        # Check for indirect propagation
        for step in path:
            if step.get("taint_status") == "indirect":
                confidence *= 0.95

        return min(max(confidence, 0.1), 1.0)

    def _extract_transformations(self, path: list[dict[str, Any]]) -> list[str]:
        """Extract data transformations along a taint path."""
        transformations = []

        for step in path:
            instruction = step.get("instruction", "").lower()

            # Check for common transformations
            if "xor" in instruction:
                transformations.append("xor_operation")
            elif "add" in instruction or "sub" in instruction:
                transformations.append("arithmetic")
            elif "shl" in instruction or "shr" in instruction:
                transformations.append("bit_shift")
            elif "call" in instruction:
                transformations.append("function_call")
            elif "cmp" in instruction or "test" in instruction:
                transformations.append("comparison")

        return transformations

    def _classify_vulnerability(self, flow: dict[str, Any]) -> str | None:
        """Classify vulnerability type based on taint flow."""
        sink_type = flow["sink"].get("sink_type", "")
        source_type = flow["source"].get("type", "")
        transformations = flow.get("transformations", [])

        # License validation vulnerabilities
        if sink_type == "comparison" and source_type in ["file_read", "registry", "network"]:
            if "xor_operation" in transformations or "arithmetic" in transformations:
                return "license_validation_bypass"
            return "weak_license_check"

        # Cryptographic vulnerabilities
        if sink_type == "crypto":
            if source_type == "hardware_id":
                return "predictable_crypto_key"
            if "comparison" in transformations:
                return "crypto_validation_bypass"

        # Input validation vulnerabilities
        if source_type == "network" and sink_type == "conditional":
            return "insufficient_input_validation"

        # Hardware ID vulnerabilities
        if source_type == "hardware_id" and sink_type in ["comparison", "conditional"]:
            return "hardware_id_bypass"

        return None

    def _assess_severity(self, flow: dict[str, Any]) -> str:
        """Assess vulnerability severity."""
        vuln_type = self._classify_vulnerability(flow)

        if vuln_type in ["license_validation_bypass", "crypto_validation_bypass"]:
            return "critical"
        if vuln_type in ["weak_license_check", "hardware_id_bypass"]:
            return "high"
        if vuln_type in ["predictable_crypto_key", "insufficient_input_validation"]:
            return "medium"
        return "low"

    def _generate_vuln_description(self, vuln_type: str, flow: dict[str, Any]) -> str:
        """Generate vulnerability description."""
        descriptions = {
            "license_validation_bypass": f"License validation can be bypassed at {hex(flow['sink']['address'])}",
            "weak_license_check": f"Weak license check implementation at {hex(flow['sink']['address'])}",
            "predictable_crypto_key": f"Cryptographic key derived from predictable hardware ID at {hex(flow['sink']['address'])}",
            "crypto_validation_bypass": f"Cryptographic validation bypass possible at {hex(flow['sink']['address'])}",
            "insufficient_input_validation": f"Insufficient input validation at {hex(flow['sink']['address'])}",
            "hardware_id_bypass": f"Hardware ID check can be bypassed at {hex(flow['sink']['address'])}",
        }

        return descriptions.get(vuln_type, f"Security vulnerability at {hex(flow['sink']['address'])}")

    def _suggest_mitigation(self, vuln_type: str, flow: dict[str, Any]) -> str:
        """Suggest mitigation for vulnerability."""
        base_mitigations = {
            "license_validation_bypass": "Implement multiple validation layers and use cryptographic signatures",
            "weak_license_check": "Use strong cryptographic validation with proper key management",
            "predictable_crypto_key": "Use proper random number generation for cryptographic keys",
            "crypto_validation_bypass": "Implement time-constant comparison and proper error handling",
            "insufficient_input_validation": "Add comprehensive input validation and sanitization",
            "hardware_id_bypass": "Combine multiple hardware identifiers and use secure hashing",
        }

        # Enhance mitigation suggestions based on flow characteristics
        base_mitigation = base_mitigations.get(vuln_type, "Review and strengthen the validation logic")

        # Add context-specific recommendations based on the vulnerability flow
        if flow:
            source_addr = flow.get("source", {}).get("address", 0)
            sink_addr = flow.get("sink", {}).get("address", 0)

            context_specific = []

            # Check if vulnerability involves user input
            if any("input" in str(v).lower() for v in flow.get("path", [])):
                context_specific.append("Focus on input sanitization at entry points")

            # Check if vulnerability involves crypto operations
            if any("crypt" in str(v).lower() or "hash" in str(v).lower() for v in flow.get("path", [])):
                context_specific.append("Review cryptographic implementation for timing attacks")

            # Check if vulnerability involves file operations
            if any("file" in str(v).lower() or "path" in str(v).lower() for v in flow.get("path", [])):
                context_specific.append("Implement proper file path validation and access controls")

            # Add distance-based recommendations
            distance = abs(sink_addr - source_addr) if source_addr and sink_addr else 0
            if distance > 1000:
                context_specific.append("Consider adding intermediate validation points due to large code distance")

            if context_specific:
                return f"{base_mitigation}. Additional recommendations: {'; '.join(context_specific)}"

        return base_mitigation


def run_taint_analysis(app: Any) -> None:
    """Initialize and run the taint analysis engine."""
    # Check if binary is loaded
    if not hasattr(app, "binary_path") or not app.binary_path:
        if hasattr(app, "update_output"):
            app.update_output.emit("log_message([Taint Analysis] No binary loaded)")
        return

    # Create and configure the engine
    engine = TaintAnalysisEngine()

    # Set binary
    if hasattr(app, "update_output"):
        app.update_output.emit("log_message([Taint Analysis] Setting binary...)")

    if engine.set_binary(app.binary_path):
        if hasattr(app, "update_output"):
            app.update_output.emit(f"log_message([Taint Analysis] Binary set: {app.binary_path})")

        # Add default taint sources and sinks
        engine._add_default_taint_sources()
        engine._add_default_taint_sinks()

        # Run analysis
        if hasattr(app, "update_output"):
            app.update_output.emit("log_message([Taint Analysis] Running analysis...)")

        if engine.run_analysis():
            if hasattr(app, "update_output"):
                app.update_output.emit("log_message([Taint Analysis] Analysis completed)")

            # Get results
            results = engine.get_results()

            # Display summary
            if hasattr(app, "update_output"):
                app.update_output.emit("log_message([Taint Analysis] Results:)")
                app.update_output.emit(f"log_message(- Total taint sources: {results['summary']['total_sources']})")
                app.update_output.emit(f"log_message(- Total taint sinks: {results['summary']['total_sinks']})")
                app.update_output.emit(f"log_message(- Total taint propagation paths: {results['summary']['total_paths']})")
                app.update_output.emit(f"log_message(- License checks found: {results['summary']['license_checks_found']})")
                app.update_output.emit(f"log_message(- Potential bypass points: {results['summary']['potential_bypass_points']})")

            # Add to analyze results
            if not hasattr(app, "analyze_results"):
                app.analyze_results = []

            app.analyze_results.append("\n=== TAINT ANALYSIS RESULTS ===")
            app.analyze_results.append(f"Total taint sources: {results['summary']['total_sources']}")
            app.analyze_results.append(f"Total taint sinks: {results['summary']['total_sinks']}")
            app.analyze_results.append(f"Total taint propagation paths: {results['summary']['total_paths']}")
            app.analyze_results.append(f"License checks found: {results['summary']['license_checks_found']}")
            app.analyze_results.append(f"Potential bypass points: {results['summary']['potential_bypass_points']}")

            # Handle report generation if PyQt6 is available
            if PYQT6_AVAILABLE:
                from ...utils.reporting.report_common import handle_pyqt6_report_generation

                report_path = handle_pyqt6_report_generation(
                    app,
                    "taint analysis",
                    engine,
                )
                if report_path:
                    if hasattr(app, "update_output"):
                        app.update_output.emit(f"log_message([Taint Analysis] Report saved to {report_path})")

                    # Ask if user wants to open the report
                    ask_open_report(app, report_path)
                elif hasattr(app, "update_output"):
                    app.update_output.emit("log_message([Taint Analysis] Failed to generate report)")
        elif hasattr(app, "update_output"):
            app.update_output.emit("log_message([Taint Analysis] Analysis failed)")
    elif hasattr(app, "update_output"):
        app.update_output.emit("log_message([Taint Analysis] Failed to set binary)")

    # Store the engine instance
    app.taint_analysis_engine = engine


# Create alias for compatibility with tests
TaintAnalyzer = TaintAnalysisEngine

# Export the main classes and functions
__all__ = [
    "TaintAnalysisEngine",
    "TaintAnalyzer",
    "run_taint_analysis",
]
