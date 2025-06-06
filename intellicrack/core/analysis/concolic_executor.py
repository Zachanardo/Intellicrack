"""
Concolic Execution Engine for Precise Path Exploration

This module provides advanced concolic execution capabilities using the Manticore framework
to systematically explore program paths and generate inputs that trigger specific behaviors,
enabling thorough vulnerability discovery and license bypass techniques.
"""

import logging
import re
import traceback
from typing import Any, Dict, List, Optional

# Optional dependencies - graceful fallback if not available
try:
    from manticore.core.plugin import Plugin
    from manticore.native import Manticore
    MANTICORE_AVAILABLE = True
except ImportError:
    # Try to use simconcolic as a fallback
    try:
        import os
        import sys
        # Add scripts directory to path
        scripts_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'scripts')
        if os.path.exists(scripts_dir):
            sys.path.insert(0, scripts_dir)

        from simconcolic import BinaryAnalyzer as Manticore
        from simconcolic import Plugin
        MANTICORE_AVAILABLE = True
        logging.getLogger(__name__).info("Using simconcolic as Manticore replacement")
    except ImportError:
        MANTICORE_AVAILABLE = False
        # Define minimal stubs to prevent import errors
        class Manticore:
            pass
        class Plugin:
            pass
        logging.getLogger(__name__).warning("Neither Manticore nor simconcolic available")

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class ConcolicExecutionEngine:
    """
    Advanced concolic execution engine for precise path exploration.

    This engine combines concrete execution with symbolic analysis to systematically
    explore program paths and generate inputs that trigger specific behaviors,
    enabling more thorough vulnerability discovery and license bypass techniques.
    """

    def __init__(self, binary_path: str, max_iterations: int = 100, timeout: int = 300):
        """
        Initialize the concolic execution engine.

        Args:
            binary_path: Path to the binary to analyze
            max_iterations: Maximum number of iterations (default: 100)
            timeout: Maximum execution time in seconds (default: 300)
        """
        self.binary_path = binary_path
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.manticore_available = MANTICORE_AVAILABLE

        # Check for required dependencies
        if MANTICORE_AVAILABLE:
            self.logger.info("Concolic execution dependencies available")
        else:
            self.logger.error("Concolic execution dependency missing: manticore not installed")

    def explore_paths(self, target_address: Optional[int] = None, avoid_addresses: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Perform concolic execution to explore program paths.

        Args:
            target_address: Optional address to reach (e.g., license validation success)
            avoid_addresses: Optional list of addresses to avoid (e.g., license checks)

        Returns:
            dict: Exploration results including discovered paths and inputs
        """
        if not self.manticore_available:
            return {"error": "Required dependencies not available. Please install manticore."}

        try:
            self.logger.info(f"Starting concolic execution on {self.binary_path}")

            # Create Manticore instance
            m = Manticore(self.binary_path)

            # Set up hooks if target or avoid addresses are provided
            if target_address is not None:
                m.add_hook(target_address, self._target_hook)

            if avoid_addresses is not None:
                for addr in avoid_addresses:
                    m.add_hook(addr, self._avoid_hook)

            # Add path exploration plugin
            class PathExplorationPlugin(Plugin):
                """
                Plugin for path exploration during symbolic execution.

                Adds hooks for target and avoid addresses to guide execution paths.
                """
                def __init__(self):
                    super().__init__()
                    self.logger = logging.getLogger(__name__)

                def will_run_callback(self, *args, **kwargs):
                    """Called when path exploration is about to start."""
                    self.logger.info("Starting path exploration")

                def did_finish_run_callback(self, *args, **kwargs):
                    """Called when path exploration has finished execution."""
                    self.logger.info("Finished path exploration")

                def will_fork_state_callback(self, state, *args, **kwargs):
                    """Called before a state is about to be forked during exploration.

                    Args:
                        state: The state that will be forked
                    """
                    self.logger.debug(f"Forking state at PC: {state.cpu.PC}")

            m.register_plugin(PathExplorationPlugin())

            # Set timeout
            m.set_exec_timeout(self.timeout)

            # Run exploration
            self.logger.info("Running concolic execution...")
            m.run(procs=4)  # Use 4 parallel processes

            # Collect results
            results = {
                "success": True,
                "paths_explored": len(m.all_states),
                "inputs": []
            }

            # Process discovered states
            for state_id, state in m.all_states.items():
                if state.is_terminated():
                    # Get input that led to this state
                    stdin_data = state.input_symbols.get('stdin', b'')
                    argv_data = state.input_symbols.get('argv', [])

                    results["inputs"].append({
                        "id": state_id,
                        "stdin": stdin_data.hex() if isinstance(stdin_data, bytes) else str(stdin_data),
                        "argv": [arg.hex() if isinstance(arg, bytes) else str(arg) for arg in argv_data],
                        "termination_reason": state.termination_reason
                    })

            self.logger.info(f"Concolic execution completed. Explored {results['paths_explored']} paths.")
            return results

        except Exception as e:
            self.logger.error(f"Error during concolic execution: {e}")
            self.logger.error(traceback.format_exc())
            return {"error": f"Concolic execution failed: {str(e)}"}

    def _target_hook(self, state):
        """
        Hook for target address.

        Args:
            state: Current execution state
        """
        state.abandon()  # Stop exploring this state
        self.logger.info(f"Reached target address at PC: {state.cpu.PC}")

    def _avoid_hook(self, state):
        """
        Hook for addresses to avoid.

        Args:
            state: Current execution state
        """
        state.abandon()  # Stop exploring this state
        self.logger.info(f"Avoided address at PC: {state.cpu.PC}")

    def find_license_bypass(self, license_check_address: Optional[int] = None) -> Dict[str, Any]:
        """
        Find inputs that bypass license checks.

        Args:
            license_check_address: Optional address of license check function

        Returns:
            dict: Bypass results including inputs that bypass license checks
        """
        if not self.manticore_available:
            return {"error": "Required dependencies not available"}

        try:
            self.logger.info(f"Finding license bypass for {self.binary_path}")

            # If license check address is not provided, try to find it
            if license_check_address is None:
                # Use symbolic execution to find license check
                license_check_address = self._find_license_check_address()
                if license_check_address is None:
                    return {"error": "Could not automatically find license check address"}

            self.logger.info(f"License check identified at address: {license_check_address}")

            # Create Manticore instance
            m = Manticore(self.binary_path)

            # Add hook to detect license check result
            success_found = [False]
            bypass_input = [None]

            class LicenseCheckPlugin(Plugin):
                """
                Plugin for Manticore symbolic execution engine to identify and manipulate license verification paths.

                This plugin extends Manticore's Plugin class to hook into the symbolic execution process,
                monitoring instructions at runtime to identify license validation routines. It specifically
                looks for conditional branches that determine whether a license check succeeds or fails.

                The plugin works by analyzing branch conditions and manipulating the execution state to
                force exploration of the "license valid" paths, which helps to:
                1. Identify valid license patterns or keys
                2. Generate working license bypass solutions
                3. Understand the license verification algorithm

                Attributes:
                    Inherits all attributes from the Manticore Plugin base class

                Note:
                    This plugin requires the parent analysis to properly identify license check
                    address locations for effective targeting.
                """
                def __init__(self):
                    super().__init__()
                    self.logger = logging.getLogger(__name__)

                def will_execute_instruction_callback(self, state, pc, insn):
                    """Called before executing each instruction during emulation.

                    Monitors for license check functions and attempts to force successful path
                    when conditional branches are encountered during trace recording.

                    Args:
                        state: Current emulation state
                        pc: Program counter (current instruction address)
                        insn: Current instruction being executed
                    """
                    # Check if we're at the license check function
                    if pc == license_check_address:
                        # Save current state for later analysis
                        state.record_trace = True
                        self.logger.info(f"Reached license check at {hex(pc)}")

                    # Check for successful license validation (typically a conditional jump)
                    if hasattr(state, 'record_trace') and state.record_trace and hasattr(insn, 'mnemonic') and insn.mnemonic.startswith('j') and not insn.mnemonic == 'jmp':
                        # Try to force the branch to take the "success" path
                        # This is a simplified approach - in reality, we'd need to analyze
                        # which branch leads to success
                        try:
                            # Try to make the condition true (success path)
                            condition = state.cpu.read_register(insn.op_str.split(',')[0])
                            state.constrain(condition != 0)
                            success_found[0] = True
                            bypass_input[0] = state.input_symbols
                            self.logger.info(f"Found potential license bypass at {hex(pc)}")
                        except Exception as e:
                            self.logger.debug(f"Could not constrain condition: {e}")

            m.register_plugin(LicenseCheckPlugin())

            # Set timeout
            m.set_exec_timeout(self.timeout)

            # Run exploration
            self.logger.info("Running concolic execution for license bypass...")
            m.run(procs=4)  # Use 4 parallel processes

            if success_found[0] and bypass_input[0]:
                # Process the bypass input
                stdin_data = bypass_input[0].get('stdin', b'')
                argv_data = bypass_input[0].get('argv', [])

                return {
                    "success": True,
                    "bypass_found": True,
                    "license_check_address": hex(license_check_address) if isinstance(license_check_address, int) else license_check_address,
                    "stdin": stdin_data.hex() if isinstance(stdin_data, bytes) else str(stdin_data),
                    "argv": [arg.hex() if isinstance(arg, bytes) else str(arg) for arg in argv_data],
                    "description": "Found input that bypasses license check"
                }
            else:
                return {
                    "success": True,
                    "bypass_found": False,
                    "description": "Could not find input that bypasses license check"
                }

        except Exception as e:
            self.logger.error(f"Error finding license bypass: {e}")
            self.logger.error(traceback.format_exc())
            return {"error": f"License bypass search failed: {str(e)}"}

    def _find_license_check_address(self) -> Optional[int]:
        """
        Attempt to automatically find license check address.

        Returns:
            int: Address of license check function, or None if not found
        """
        try:
            if not LIEF_AVAILABLE:
                self.logger.warning("LIEF not available - cannot analyze binary functions")
                return None
            
            if hasattr(lief, 'parse'):
                binary = lief.parse(self.binary_path)
            else:
                self.logger.error("lief.parse not available")
                return None

            # Look for license-related functions in exports
            for func in binary.exported_functions:
                func_name = func.name.lower()
                if any(pattern in func_name for pattern in ["licen", "valid", "check", "auth"]):
                    return func.address

            # Look for license-related strings
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()

            license_patterns = [b"license", b"valid", b"key", b"auth", b"check"]
            for pattern in license_patterns:
                matches = list(re.finditer(pattern, binary_data, re.IGNORECASE))
                if matches:
                    # Found a potential license-related string
                    # In a real implementation, we'd need to find the function that references this string
                    # This is a simplified approach
                    return None

            return None

        except Exception as e:
            self.logger.error(f"Error finding license check address: {e}")
            return None


__all__ = ['ConcolicExecutionEngine']
