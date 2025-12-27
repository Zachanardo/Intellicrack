"""Fixed concolic executor for Intellicrack core analysis.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from typing import Any


"""
Concolic Execution Engine for Precise Path Exploration

This module provides a unified interface for symbolic execution using:
1. angr (primary, cross-platform)
2. manticore (secondary, Linux-only)
3. simconcolic (fallback)
"""

logger: logging.Logger = logging.getLogger(__name__)

# Try to import symbolic execution engines in priority order
SYMBOLIC_ENGINE: str | None = None
SYMBOLIC_ENGINE_NAME: str | None = None

# First try angr (cross-platform, recommended)
try:
    import angr
    import claripy

    SYMBOLIC_ENGINE = "angr"
    SYMBOLIC_ENGINE_NAME = "angr"
    ANGR_AVAILABLE: bool = True
except ImportError:
    ANGR_AVAILABLE = False

# Try simconcolic fallback if angr not available
if not SYMBOLIC_ENGINE:
    try:
        from .simconcolic import BinaryAnalyzer as SimConcolic  # :no-index:

        SYMBOLIC_ENGINE = "simconcolic"
        SYMBOLIC_ENGINE_NAME = "simconcolic"
        SIMCONCOLIC_AVAILABLE: bool = True
    except ImportError:
        SIMCONCOLIC_AVAILABLE = False

# Manticore is no longer supported (Windows-only focus)
MANTICORE_AVAILABLE: bool = False


class ConcolicExecutionEngine:
    """Unified concolic execution engine supporting multiple backends."""

    def __init__(self, binary_path: str, max_iterations: int = 100, timeout: int = 300) -> None:
        """Initialize the concolic execution engine.

        Sets up the unified concolic execution engine with support for multiple
        symbolic execution backends including angr, manticore, and simconcolic.
        Automatically selects the best available engine for the platform.

        Args:
            binary_path: Path to the binary to analyze
            max_iterations: Maximum number of exploration iterations
            timeout: Execution timeout in seconds

        """
        self.binary_path = binary_path
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.symbolic_engine = SYMBOLIC_ENGINE
        self.symbolic_engine_name = SYMBOLIC_ENGINE_NAME

        # Log available engine
        if self.symbolic_engine:
            self.logger.info("Using %s for symbolic execution", self.symbolic_engine_name)
        else:
            self.logger.error("No symbolic execution engine available!", exc_info=True)

    @property
    def manticore_available(self) -> bool:
        """Legacy property for backward compatibility."""
        return self.symbolic_engine is not None

    def explore_paths(self, target_address: int | None = None, avoid_addresses: list[int] | None = None) -> dict[str, Any]:
        """Explore paths using the available symbolic execution engine."""
        if not self.symbolic_engine:
            return {"error": "No symbolic execution engine available. Install angr (recommended)."}

        if self.symbolic_engine == "angr":
            return self._explore_paths_angr(target_address, avoid_addresses)
        if self.symbolic_engine == "simconcolic":
            return self._explore_paths_simconcolic(target_address, avoid_addresses)

        return {"error": "Unknown symbolic execution engine"}

    def _explore_paths_angr(self, target_address: int | None, avoid_addresses: list[int] | None) -> dict[str, Any]:
        """Explore paths using angr."""
        try:
            self.logger.info("Starting angr symbolic execution on %s", self.binary_path)

            # Create angr project
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Create initial state
            state = project.factory.entry_state()

            # Add symbolic variables for input if available
            if ANGR_AVAILABLE and claripy:
                # Create symbolic input for stdin
                sym_stdin_size: int = 0x100
                sym_stdin = claripy.BVS("stdin", sym_stdin_size * 8)
                state.posix.stdin.write(0, sym_stdin, sym_stdin_size)
                state.posix.stdin.seek(0)

            # Create symbolic execution state manager for path exploration
            # This is angr's real symbolic execution engine that analyzes actual binary paths
            exec_manager: Any = project.factory.simgr(state)  # type: ignore[no-untyped-call]

            # Set up find and avoid addresses
            find_addrs: list[int] = [target_address] if target_address else []
            avoid_addrs: list[int] = avoid_addresses or []

            # Perform symbolic execution path exploration
            exec_manager.explore(find=find_addrs, avoid=avoid_addrs, n=self.max_iterations)

            results: dict[str, Any] = {
                "success": True,
                "engine": "angr",
                "paths_explored": len(exec_manager.deadended) + len(exec_manager.active),
                "target_reached": len(exec_manager.found) > 0,
                "avoided_addresses": len(exec_manager.avoided),
                "inputs": [],
            }

            # Extract inputs that reach target
            for found_state in exec_manager.found:
                if found_state.posix.stdin.load(0, found_state.posix.stdin.size):
                    stdin_data: bytes = found_state.posix.dumps(0)
                    inputs_list: list[dict[str, Any]] = results["inputs"]
                    inputs_list.append(
                        {
                            "stdin": stdin_data.hex() if stdin_data else None,
                            "constraints": len(found_state.solver.constraints),
                        },
                    )

            return results

        except Exception as e:
            self.logger.exception("Angr execution failed: %s", e)
            return {"error": str(e), "engine": "angr"}

    def _explore_paths_simconcolic(self, target_address: int | None, avoid_addresses: list[int] | None) -> dict[str, Any]:
        """Fallback simconcolic implementation."""
        if not SIMCONCOLIC_AVAILABLE:
            return {
                "success": False,
                "engine": "simconcolic",
                "error": "SimConcolic not available",
            }

        try:
            # Use the imported SimConcolic analyzer
            analyzer: Any = SimConcolic(self.binary_path)

            # Run basic analysis using the run method which is the primary API
            states: list[Any] = analyzer.run(timeout=self.timeout, procs=1)

            # Process exploration results from states
            paths_explored: int = len(states)
            target_reached: bool = any(getattr(state, "pc", None) == target_address for state in states)

            # Extract inputs from states
            inputs: list[dict[str, Any]] = []
            for state in states:
                if hasattr(state, "input_symbols") and isinstance(state.input_symbols, dict):
                    stdin_data: Any = state.input_symbols.get("stdin")
                    if stdin_data:
                        if isinstance(stdin_data, bytes):
                            inputs.append({
                                "stdin": stdin_data.hex(),
                                "address": hex(getattr(state, "pc", 0)),
                            })
                        elif isinstance(stdin_data, str):
                            inputs.append({
                                "stdin": stdin_data.encode().hex(),
                                "address": hex(getattr(state, "pc", 0)),
                            })

            return {
                "success": True,
                "engine": "simconcolic",
                "paths_explored": paths_explored,
                "target_reached": target_reached,
                "inputs": inputs,
            }
        except Exception as e:
            return {
                "success": False,
                "engine": "simconcolic",
                "error": f"SimConcolic analysis failed: {e!s}",
            }

    def find_license_bypass(self) -> dict[str, Any]:
        """Find license bypass using available engine."""
        if self.symbolic_engine == "angr":
            return self._find_license_bypass_angr()
        if self.symbolic_engine == "simconcolic":
            return {"error": "SimConcolic does not support license bypass analysis"}
        return {"error": "No suitable symbolic execution engine for license bypass"}

    def _find_license_bypass_angr(self) -> dict[str, Any]:
        """Find license bypass using angr."""
        try:
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Common license check patterns
            license_patterns: list[bytes] = [
                b"Invalid license",
                b"License expired",
                b"Unregistered",
                b"Trial version",
            ]

            # Search for license check functions
            cfg = project.analyses.CFGFast()
            license_addrs: list[int] = []
            string_refs: list[dict[str, Any]] = []

            # First, find string references to license patterns
            for pattern in license_patterns:
                try:
                    # Search for pattern in binary
                    for addr in project.loader.main_object.memory.find(pattern):
                        # Find cross-references to this string
                        xrefs = project.analyses.Xrefs(pattern, memory_only=True)
                        for xref in xrefs:
                            string_refs.append(
                                {
                                    "pattern": pattern.decode("utf-8", errors="ignore"),
                                    "string_addr": addr,
                                    "ref_addr": xref.addr,
                                },
                            )
                            license_addrs.append(xref.addr)
                except Exception as e:
                    logger.debug("Failed to search for pattern %s: %s", pattern, e)

            for func in cfg.functions.values():
                # Look for functions that might be license checks
                if any(pattern in func.name.lower() for pattern in ["license", "register", "validate", "check"]):
                    license_addrs.append(func.addr)

            if not license_addrs:
                return {
                    "success": False,
                    "bypass_found": False,
                    "reason": "No license functions found",
                }

            # Try to find bypass
            state = project.factory.entry_state()

            # Add symbolic license key for testing
            if ANGR_AVAILABLE and claripy:
                # Create symbolic license key
                license_key_size: int = 32
                sym_license_key = claripy.BVS("license_key", license_key_size * 8)
                # Store it in symbolic memory for the program to use
                license_key_addr: int = 0x10000000
                state.memory.store(license_key_addr, sym_license_key)  # type: ignore[no-untyped-call]

            exec_mgr: Any = project.factory.simgr(state)  # type: ignore[no-untyped-call]

            # Explore avoiding license checks
            exec_mgr.explore(avoid=license_addrs[:5])

            if exec_mgr.found or exec_mgr.deadended:
                return {
                    "success": True,
                    "bypass_found": True,
                    "engine": "angr",
                    "license_check_addresses": [hex(addr) for addr in license_addrs],
                    "license_string_references": string_refs,
                    "bypass_method": "Path avoidance",
                    "patterns_found": len(string_refs),
                }

            return {
                "success": True,
                "bypass_found": False,
                "license_string_references": string_refs,
                "patterns_found": len(string_refs),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}


# Adding exports to concolic_executor_fixed.py

__all__ = [
    "ANGR_AVAILABLE",
    "ConcolicExecutionEngine",
    "SIMCONCOLIC_AVAILABLE",
    "SYMBOLIC_ENGINE",
    "SYMBOLIC_ENGINE_NAME",
]
