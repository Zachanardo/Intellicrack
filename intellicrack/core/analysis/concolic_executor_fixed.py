"""This file is part of Intellicrack.
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

logger = logging.getLogger(__name__)

# Try to import symbolic execution engines in priority order
SYMBOLIC_ENGINE = None
SYMBOLIC_ENGINE_NAME = None

# First try angr (cross-platform, recommended)
try:
    import angr
    import claripy

    SYMBOLIC_ENGINE = "angr"
    SYMBOLIC_ENGINE_NAME = "angr"
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

# Then try manticore (Linux-only)
if not SYMBOLIC_ENGINE:
    try:
        from manticore.core.plugin import Plugin
        from manticore.native import Manticore

        SYMBOLIC_ENGINE = "manticore"
        SYMBOLIC_ENGINE_NAME = "manticore"
        MANTICORE_AVAILABLE = True
    except ImportError:
        MANTICORE_AVAILABLE = False
        Plugin = None
        Manticore = None

# Finally try simconcolic fallback
if not SYMBOLIC_ENGINE:
    try:
        from .simconcolic import BinaryAnalyzer as SimConcolic  # :no-index:

        SYMBOLIC_ENGINE = "simconcolic"
        SYMBOLIC_ENGINE_NAME = "simconcolic"
        SIMCONCOLIC_AVAILABLE = True
    except ImportError:
        SIMCONCOLIC_AVAILABLE = False


class ConcolicExecutionEngine:
    """Unified concolic execution engine supporting multiple backends."""

    def __init__(self, binary_path: str, max_iterations: int = 100, timeout: int = 300):
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
            self.logger.info(f"Using {self.symbolic_engine_name} for symbolic execution")
        else:
            self.logger.error("No symbolic execution engine available!")

    @property
    def manticore_available(self):
        """Legacy property for backward compatibility."""
        return self.symbolic_engine is not None

    def explore_paths(self, target_address: int | None = None, avoid_addresses: list[int] | None = None) -> dict[str, Any]:
        """Explore paths using the available symbolic execution engine."""
        if not self.symbolic_engine:
            return {"error": "No symbolic execution engine available. Install angr (recommended) or manticore (Linux)."}

        if self.symbolic_engine == "angr":
            return self._explore_paths_angr(target_address, avoid_addresses)
        if self.symbolic_engine == "manticore":
            return self._explore_paths_manticore(target_address, avoid_addresses)
        if self.symbolic_engine == "simconcolic":
            return self._explore_paths_simconcolic(target_address, avoid_addresses)

    def _explore_paths_angr(self, target_address, avoid_addresses):
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
                sym_stdin_size = 0x100  # 256 bytes
                sym_stdin = claripy.BVS("stdin", sym_stdin_size * 8)
                state.posix.stdin.write(0, sym_stdin, sym_stdin_size)
                state.posix.stdin.seek(0)

            # Create simulation manager
            simgr = project.factory.simulation_manager(state)

            # Set up find and avoid addresses
            find_addrs = [target_address] if target_address else []
            avoid_addrs = avoid_addresses if avoid_addresses else []

            # Explore with constraints
            simgr.explore(find=find_addrs, avoid=avoid_addrs, n=self.max_iterations)

            results = {
                "success": True,
                "engine": "angr",
                "paths_explored": len(simgr.deadended) + len(simgr.active),
                "target_reached": len(simgr.found) > 0,
                "avoided_addresses": len(simgr.avoided),
                "inputs": [],
            }

            # Extract inputs that reach target
            for found_state in simgr.found:
                if found_state.posix.stdin.load(0, found_state.posix.stdin.size):
                    stdin_data = found_state.posix.dumps(0)
                    results["inputs"].append(
                        {
                            "stdin": stdin_data.hex() if stdin_data else None,
                            "constraints": len(found_state.solver.constraints),
                        }
                    )

            return results

        except Exception as e:
            self.logger.error(f"Angr execution failed: {e}")
            return {"error": str(e), "engine": "angr"}

    def _explore_paths_manticore(self, target_address, avoid_addresses):
        """Explore paths using manticore (Linux only)."""
        if not MANTICORE_AVAILABLE:
            return {"error": "Manticore not available on this platform"}

        try:
            self.logger.info("Starting manticore symbolic execution on %s", self.binary_path)

            # Create Manticore instance
            m = Manticore(self.binary_path)

            # Set up hooks if provided
            if target_address:
                m.add_hook(target_address, lambda state: state.abandon())

            if avoid_addresses:
                for addr in avoid_addresses:
                    m.add_hook(addr, lambda state: state.abandon())

            # Run exploration
            m.run()

            results = {
                "success": True,
                "engine": "manticore",
                "paths_explored": len(m.terminated_states),
                "target_reached": False,  # Would need custom tracking
                "inputs": [],
            }

            return results

        except Exception as e:
            self.logger.error(f"Manticore execution failed: {e}")
            return {"error": str(e), "engine": "manticore"}

    def _explore_paths_simconcolic(self, target_address, avoid_addresses):
        """Fallback simconcolic implementation."""
        if not SIMCONCOLIC_AVAILABLE:
            return {
                "success": False,
                "engine": "simconcolic",
                "error": "SimConcolic not available",
            }

        try:
            # Use the imported SimConcolic analyzer
            analyzer = SimConcolic(self.binary_path)

            # Run basic analysis
            results = analyzer.analyze(
                target_address=target_address,
                avoid_addresses=avoid_addresses,
                max_iterations=self.max_iterations,
            )

            return {
                "success": True,
                "engine": "simconcolic",
                "paths_explored": results.get("paths_explored", 0),
                "target_reached": results.get("target_reached", False),
                "inputs": results.get("inputs", []),
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
        if self.symbolic_engine == "manticore":
            return self._find_license_bypass_manticore()
        return {"error": "No suitable symbolic execution engine for license bypass"}

    def _find_license_bypass_angr(self):
        """Find license bypass using angr."""
        try:
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Common license check patterns
            license_patterns = [
                b"Invalid license",
                b"License expired",
                b"Unregistered",
                b"Trial version",
            ]

            # Search for license check functions
            cfg = project.analyses.CFGFast()
            license_addrs = []
            string_refs = []

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
                                }
                            )
                            license_addrs.append(xref.addr)
                except Exception as e:
                    logger.debug(f"Failed to search for pattern {pattern}: {e}")

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
                license_key_size = 32  # 32 byte license key
                sym_license_key = claripy.BVS("license_key", license_key_size * 8)
                # Store it in symbolic memory for the program to use
                license_key_addr = 0x10000000  # Arbitrary address in mapped memory
                state.memory.store(license_key_addr, sym_license_key)

            simgr = project.factory.simulation_manager(state)

            # Explore avoiding license checks
            simgr.explore(avoid=license_addrs[:5])  # Limit to first 5

            if simgr.found or simgr.deadended:
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

    def _find_license_bypass_manticore(self):
        """Find license bypass using manticore."""
        if not MANTICORE_AVAILABLE:
            return {"error": "Manticore not available"}

        # Similar implementation to angr but using manticore API
        return {"success": False, "error": "Manticore license bypass not implemented"}


# Adding exports to concolic_executor_fixed.py

__all__ = [
    "ConcolicExecutionEngine",
    "SYMBOLIC_ENGINE",
    "SYMBOLIC_ENGINE_NAME",
    "ANGR_AVAILABLE",
    "MANTICORE_AVAILABLE",
    "SIMCONCOLIC_AVAILABLE",
]
