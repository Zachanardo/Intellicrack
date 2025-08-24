import logging

from intellicrack.utils.log_message import log_message

logger = logging.getLogger(__name__)

class SymbolicExecution:
    def run_symbolic_execution(self, app, *args, **kwargs):
        """Run symbolic execution analysis on binary."""
        _ = args, kwargs
        try:
            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message("[Symbolic] Starting symbolic execution analysis...")
                )

            # Validate binary path
            binary_path = self._validate_symbolic_binary_path(app)
            if not binary_path:
                return {"success": False, "error": "No binary selected"}

            # Initialize results structure
            results = self._initialize_symbolic_results(binary_path)

            # Try angr-based symbolic execution first
            if self._attempt_angr_symbolic_execution(app, binary_path, results):
                return results

            # Fall back to pattern-based analysis
            self._perform_fallback_symbolic_analysis(app, binary_path, results)

            # Update UI with results
            self._update_symbolic_ui_results(app, binary_path, results)

            return results

        except (AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) as e:
            logger.error("(AttributeError, ValueError, TypeError, RuntimeError, KeyError, OSError, IOError) in main_app.py: %s", e)
            error_msg = f"Error during symbolic execution: {str(e)}"
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message(f"[Symbolic] {error_msg}"))
            return {"success": False, "error": error_msg}


    def _validate_symbolic_binary_path(self, app):
        """Validate that a binary is selected for symbolic execution."""
        binary_path = getattr(app, "binary_path", None)
        if not binary_path:
            if hasattr(app, "update_output"):
                app.update_output.emit(log_message("[Symbolic] Error: No binary selected"))
        return binary_path

    def _initialize_symbolic_results(self, binary_path):
        """Initialize symbolic execution results structure."""
        return {
            "success": True,
            "binary_path": binary_path,
            "constraints": [],
            "paths": [],
            "vulnerabilities": [],
            "inputs": [],
        }

    def _attempt_angr_symbolic_execution(self, app, binary_path, results):
        """Attempt symbolic execution using angr framework."""
        try:
            import angr
            import claripy

            if hasattr(app, "update_output"):
                # Check angr version and capabilities
                angr_version = getattr(angr, '__version__', 'unknown')
                claripy_backends = len(claripy.backends.all_backends) if hasattr(claripy, 'backends') else 0

                app.update_output.emit(
                    log_message(f"[Symbolic] Loading binary with angr v{angr_version} (claripy backends: {claripy_backends})")
                )

            # Setup angr project and simulation manager
            simgr = self._setup_angr_simulation(binary_path, angr)

            # Run symbolic exploration
            steps, found_paths = self._run_symbolic_exploration(app, simgr, results)

            # Extract symbolic inputs
            self._extract_symbolic_inputs(app, simgr, results, claripy)

            # Update results summary
            results["summary"] = self._create_angr_summary(simgr, steps, found_paths)

            if hasattr(app, "update_output"):
                app.update_output.emit(
                    log_message(
                        f"[Symbolic] Analysis complete. Found {found_paths} paths, {len(results['vulnerabilities'])} potential vulnerabilities"
                    )
                )
            return True

        except ImportError:
            return False

    def _setup_angr_simulation(self, binary_path, angr):
        """Setup angr project and simulation manager with exploration techniques."""
        # Create angr project
        proj = angr.Project(binary_path, auto_load_libs=False)

        # Create initial state
        state = proj.factory.entry_state()

        # Create simulation manager
        simgr = proj.factory.simulation_manager(state)

        # Configure exploration techniques
        if hasattr(angr, "exploration_techniques"):
            # Add memory limiter if available
            if hasattr(angr.exploration_techniques, "MemoryLimiter"):
                simgr.use_technique(
                    angr.exploration_techniques.MemoryLimiter(4096)
                )  # 4GB limit

            # Add timeout if available
            if hasattr(angr.exploration_techniques, "Timeout"):
                simgr.use_technique(
                    angr.exploration_techniques.Timeout(300)
                )  # 5 minute timeout

        return simgr

    def _run_symbolic_exploration(self, app, simgr, results):
        """Run symbolic execution exploration with limits."""
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message("[Symbolic] Exploring execution paths..."))

        steps = 0
        max_steps = 1000
        found_paths = 0
        max_paths = 10

        while simgr.active and steps < max_steps and found_paths < max_paths:
            simgr.step()
            steps += 1

            # Process interesting states
            found_paths += self._process_simulation_states(simgr, results)

        return steps, found_paths

    def _process_simulation_states(self, simgr, results):
        """Process interesting states from simulation manager."""
        found_paths = 0

        # Check for interesting states
        for stash in ["deadended", "found", "errored"]:
            if hasattr(simgr, stash) and len(getattr(simgr, stash)) > 0:
                for state in getattr(simgr, stash):
                    path_info = self._create_path_info(state, stash)
                    self._extract_state_constraints(state, results)
                    self._check_vulnerability_state(state, stash, path_info, results)

                    results["paths"].append(path_info)
                    found_paths += 1

        return found_paths

    def _create_path_info(self, state, stash):
        """Create path information from simulation state."""
        return {
            "stash": stash,
            "address": hex(state.addr) if hasattr(state, "addr") else "unknown",
            "constraints": len(state.solver.constraints) if hasattr(state, "solver") else 0,
            "satisfiable": state.solver.satisfiable() if hasattr(state, "solver") else False,
        }

    def _extract_state_constraints(self, state, results):
        """Extract constraints from simulation state."""
        if hasattr(state, "solver") and hasattr(state.solver, "constraints"):
            for constraint in list(state.solver.constraints)[:5]:  # First 5 constraints
                results["constraints"].append(str(constraint))

    def _check_vulnerability_state(self, state, stash, path_info, results):
        """Check if state represents a potential vulnerability."""
        if stash == "errored":
            vuln = {
                "type": "crash",
                "address": path_info["address"],
                "severity": "high",
                "description": "Symbolic execution found a crash path",
            }
            results["vulnerabilities"].append(vuln)

    def _extract_symbolic_inputs(self, app, simgr, results, claripy):
        """Extract symbolic inputs from deadended states."""
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message("[Symbolic] Extracting symbolic inputs..."))

        for state in simgr.deadended[:5]:  # Analyze first 5 deadended states
            symbolic_vars = self._find_symbolic_variables(state, claripy)

            if symbolic_vars:
                results["inputs"].append({
                    "path_address": hex(state.addr) if hasattr(state, "addr") else "unknown",
                    "symbolic_variables": symbolic_vars,
                })

    def _find_symbolic_variables(self, state, claripy):
        """Find symbolic variables in a simulation state."""
        symbolic_vars = []
        if hasattr(state, "solver") and hasattr(state.solver, "_solver"):
            for var in state.solver._solver.variables():
                if isinstance(var, claripy.ast.BV):
                    symbolic_vars.append({
                        "name": str(var),
                        "size": var.size() if hasattr(var, "size") else 0,
                    })
        return symbolic_vars

    def _create_angr_summary(self, simgr, steps, found_paths):
        """Create summary for angr-based symbolic execution."""
        return {
            "total_paths": found_paths,
            "active_paths": len(simgr.active),
            "deadended_paths": len(simgr.deadended),
            "errored_paths": len(simgr.errored) if hasattr(simgr, "errored") else 0,
            "steps_executed": steps,
        }

    def _perform_fallback_symbolic_analysis(self, app, binary_path, results):
        """Perform fallback symbolic analysis using pattern matching."""
        if hasattr(app, "update_output"):
            app.update_output.emit(
                log_message("[Symbolic] Angr not available, using basic symbolic analysis...")
            )

        import os

        # Read binary data
        file_size = os.path.getsize(binary_path)
        with open(binary_path, "rb") as f:
            data = f.read(min(file_size, 1024 * 1024))  # Read first 1MB

        # Analyze patterns
        self._analyze_symbolic_patterns(data, results)

        # Update results summary
        results["summary"] = {
            "total_paths": len(results["paths"]),
            "analysis_type": "static_pattern_matching",
            "file_size": file_size,
        }

        if hasattr(app, "update_output"):
            app.update_output.emit(
                log_message(f"[Symbolic] Basic analysis complete. Found {len(results['paths'])} interesting points")
            )

    def _analyze_symbolic_patterns(self, data, results):
        """Analyze binary data for symbolic execution patterns."""
        # Look for interesting patterns
        patterns = [
            (b"strcmp", "String comparison - potential authentication"),
            (b"memcmp", "Memory comparison - potential key check"),
            (b"if", "Conditional branch"),
            (b"jz", "Jump if zero - conditional execution"),
            (b"jnz", "Jump if not zero - conditional execution"),
            (b"test", "Test instruction - flag setting"),
            (b"cmp", "Compare instruction - potential check"),
        ]

        # Use common utility for pattern searching
        from ..utils.binary.binary_io import find_all_pattern_offsets

        for pattern, description in patterns:
            offsets = find_all_pattern_offsets(data, pattern)
            for pos in offsets:
                results["paths"].append({
                    "stash": "potential",
                    "address": hex(pos),
                    "description": description
                })

                # Add as potential vulnerability if it's a comparison
                if b"cmp" in pattern or b"strcmp" in pattern:
                    results["vulnerabilities"].append({
                        "type": "authentication_check",
                        "address": hex(pos),
                        "severity": "medium",
                        "description": f"{description} - may be bypassable",
                    })

                offset = pos + 1
                logger.debug("Next search offset: %d", offset)

    def _update_symbolic_ui_results(self, app, binary_path, results):
        """Update UI with symbolic execution results."""
        if not hasattr(app, "update_analysis_results"):
            return

        import os

        app.update_analysis_results.emit("\n=== Symbolic Execution Results ===\n")
        app.update_analysis_results.emit(f"Binary: {os.path.basename(binary_path)}\n")
        app.update_analysis_results.emit(
            f"Analysis Type: {results['summary'].get('analysis_type', 'symbolic_execution')}\n"
        )
        app.update_analysis_results.emit(
            f"Total Paths: {results['summary'].get('total_paths', 0)}\n"
        )

        # Show vulnerabilities
        if results["vulnerabilities"]:
            app.update_analysis_results.emit(
                f"\nPotential Vulnerabilities ({len(results['vulnerabilities'])}):\n"
            )
            for vuln in results["vulnerabilities"][:10]:  # Show first 10
                app.update_analysis_results.emit(
                    f"  [{vuln['severity'].upper()}] {vuln['type']} at {vuln['address']}: {vuln['description']}\n"
                )

        # Show execution paths
        if results["paths"]:
            app.update_analysis_results.emit(
                f"\nExecution Paths ({len(results['paths'])}):\n"
            )
            for path in results["paths"][:10]:  # Show first 10
                app.update_analysis_results.emit(
                    f"  - {path.get('stash', 'unknown')} at {path.get('address', 'unknown')}"
                )
                if "description" in path:
                    app.update_analysis_results.emit(f" - {path['description']}")
                app.update_analysis_results.emit("\n")
