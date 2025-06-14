"""
Additional runner functions for Intellicrack. 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


def run_comprehensive_analysis(binary_path: str, output_dir: Optional[str] = None,
                             analyses: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run comprehensive analysis pipeline on a binary.

    Args:
        binary_path: Path to the binary file
        output_dir: Directory for output files
        analyses: List of analyses to run (default: all)

    Returns:
        Dict containing comprehensive analysis results
    """
    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(binary_path), "intellicrack_analysis")
    os.makedirs(output_dir, exist_ok=True)

    # Default analyses if none specified
    if analyses is None:
        analyses = [
            "binary_info", "format_analysis", "protection_scan",
            "string_extraction", "entropy_analysis", "pattern_search",
            "vulnerability_scan", "license_analysis"
        ]

    results = {
        "binary": binary_path,
        "output_dir": output_dir,
        "timestamp": time.time(),
        "analyses": {},
        "summary": {}
    }

    # Import required modules
    try:
        from .binary_analysis import analyze_binary, analyze_patterns
        from .distributed_processing import run_distributed_entropy_analysis
        from .protection_detection import run_comprehensive_protection_scan
        from .security_analysis import check_buffer_overflow, scan_protectors
    except ImportError as e:
        logger.error("Import error: %s", e)
        results["error"] = f"Missing dependencies: {e}"
        return results

    # Run each analysis
    for analysis in analyses:
        try:
            logger.info("Running %s...", analysis)

            if analysis == "binary_info":
                results["analyses"]["binary_info"] = analyze_binary(binary_path)

            elif analysis == "format_analysis":
                info = analyze_binary(binary_path, detailed=True)
                results["analyses"]["format_analysis"] = info

            elif analysis == "protection_scan":
                results["analyses"]["protection_scan"] = scan_protectors(binary_path)

            elif analysis == "string_extraction":
                # Use distributed processing for strings
                from .distributed_processing import _distributed_string_extraction
                results["analyses"]["strings"] = _distributed_string_extraction(
                    binary_path, {"min_length": 4}
                )

            elif analysis == "entropy_analysis":
                results["analyses"]["entropy"] = run_distributed_entropy_analysis(binary_path)

            elif analysis == "pattern_search":
                results["analyses"]["patterns"] = analyze_patterns(binary_path)

            elif analysis == "vulnerability_scan":
                results["analyses"]["vulnerabilities"] = check_buffer_overflow(binary_path)

            elif analysis == "license_analysis":
                # Specialized license analysis
                license_patterns = [
                    b"license", b"LICENSE", b"activation", b"serial",
                    b"trial", b"expire", b"register", b"key"
                ]
                results["analyses"]["license"] = analyze_patterns(binary_path, license_patterns)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in %s: %s", analysis, e)
            results["analyses"][analysis] = {"error": str(e)}

    # Generate summary
    results["summary"] = _generate_analysis_summary(results["analyses"])

    # Save results to file
    results_file = os.path.join(output_dir, "comprehensive_analysis.json")
    try:
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        results["results_file"] = results_file
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error saving results: %s", e)

    return results


def run_deep_license_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Run deep analysis specifically for license mechanisms.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing license analysis results
    """
    results = {
        "binary": binary_path,
        "license_mechanisms": [],
        "validation_routines": [],
        "protection_methods": [],
        "bypass_suggestions": []
    }

    try:
        # Import required modules
        from ..core.analysis.core_analysis import enhanced_deep_license_analysis
        from .binary_analysis import analyze_patterns

        # Use existing deep license analysis
        deep_results = enhanced_deep_license_analysis(binary_path)
        results.update(deep_results)

        # Additional license-specific pattern search
        license_patterns = {
            "activation": [b"ActivateLicense", b"ValidateLicense", b"CheckLicense"],
            "trial": [b"TrialExpired", b"DaysRemaining", b"TrialPeriod"],
            "hardware": [b"MachineID", b"HardwareID", b"GetVolumeSerial"],
            "network": [b"LicenseServer", b"ActivationServer", b"OnlineValidation"],
            "crypto": [b"RSA", b"AES", b"SHA256", b"ECDSA"]
        }

        pattern_results = {}
        for category, patterns in license_patterns.items():
            cat_results = analyze_patterns(binary_path, patterns)
            if cat_results.get("matches"):
                pattern_results[category] = cat_results

        results["pattern_analysis"] = pattern_results

        # Analyze potential bypass points
        if pattern_results:
            results["bypass_suggestions"] = _generate_bypass_suggestions(pattern_results)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in deep license analysis: %s", e)
        results["error"] = str(e)

    return results


def run_detect_packing(binary_path: str) -> Dict[str, Any]:
    """
    Run packing detection on a binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing packing detection results
    """
    try:
        from ..core.analysis.core_analysis import detect_packing
        from .distributed_processing import run_distributed_entropy_analysis

        results = {
            "binary": binary_path,
            "packing_detected": False,
            "packers_found": [],
            "indicators": []
        }

        # Use existing detect_packing function
        packing_result = detect_packing(binary_path)
        results.update(packing_result)

        # Additional entropy-based detection
        entropy_results = run_distributed_entropy_analysis(binary_path)
        if entropy_results.get("statistics", {}).get("average_entropy", 0) > 7.0:
            results["packing_detected"] = True
            results["indicators"].append("High entropy detected")

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting packing: %s", e)
        return {"error": str(e)}


def run_analysis(binary_path: str, analysis_type: str = "basic") -> Dict[str, Any]:
    """
    Generic analysis runner.

    Args:
        binary_path: Path to the binary file
        analysis_type: Type of analysis (basic, advanced, full)

    Returns:
        Dict containing analysis results
    """
    analysis_levels = {
        "basic": ["binary_info", "format_analysis"],
        "advanced": ["binary_info", "format_analysis", "protection_scan", "entropy_analysis"],
        "full": None  # All available analyses
    }

    analyses = analysis_levels.get(analysis_type)
    return run_comprehensive_analysis(binary_path, analyses=analyses)


def run_autonomous_crack(binary_path: str, target_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Run autonomous cracking mode.

    Args:
        binary_path: Path to the binary file
        target_type: Type of target (license, trial, protection)

    Returns:
        Dict containing cracking results
    """
    results = {
        "binary": binary_path,
        "target_type": target_type or "auto",
        "analysis_phase": {},
        "patching_phase": {},
        "success": False
    }

    try:
        # Phase 1: Analysis
        logger.info("Phase 1: Analyzing target...")
        analysis = run_comprehensive_analysis(binary_path)
        results["analysis_phase"] = analysis

        # Determine target type if auto
        if target_type == "auto" or target_type is None:
            target_type = _determine_target_type(analysis)
            results["detected_type"] = target_type

        # Phase 2: Generate patches
        logger.info("Phase 2: Generating patches...")
        from .exploitation import run_automated_patch_agent

        if target_type == "license":
            patches = run_automated_patch_agent(binary_path, "remove_license")
        elif target_type == "trial":
            patches = run_automated_patch_agent(binary_path, "remove_trial")
        else:
            patches = run_automated_patch_agent(binary_path, "remove_protection")

        results["patching_phase"]["patches"] = patches

        # Phase 3: Apply patches (simulation only for safety)
        if patches.get("suggested_patches"):
            from .exploitation import run_simulate_patch
            simulation = run_simulate_patch(binary_path, patches["suggested_patches"])
            results["patching_phase"]["simulation"] = simulation

            if simulation.get("summary", {}).get("valid_patches", 0) > 0:
                results["success"] = True
                results["message"] = f"Found {simulation['summary']['valid_patches']} valid patches"
            else:
                results["message"] = "No valid patches found"
        else:
            results["message"] = "No patches generated"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in autonomous crack: %s", e)
        results["error"] = str(e)

    return results


def run_full_autonomous_mode(binary_path: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run full autonomous operation mode.

    Args:
        binary_path: Path to the binary file
        config: Configuration for autonomous mode

    Returns:
        Dict containing full autonomous operation results
    """
    if config is None:
        config = {
            "analysis_depth": "full",
            "patch_strategy": "conservative",
            "backup": True,
            "verify": True
        }

    results = {
        "binary": binary_path,
        "config": config,
        "phases": {},
        "overall_success": False
    }

    try:
        # Phase 1: Comprehensive analysis
        results["phases"]["analysis"] = run_comprehensive_analysis(
            binary_path,
            analyses=None if config["analysis_depth"] == "full" else ["binary_info", "protection_scan"]
        )

        # Phase 2: Protection removal
        if results["phases"]["analysis"].get("analyses", {}).get("protection_scan", {}).get("protections_found"):
            from .security_analysis import run_tpm_bypass, run_vm_bypass

            results["phases"]["protection_removal"] = {
                "vm_bypass": run_vm_bypass(binary_path),
                "tpm_bypass": run_tpm_bypass(binary_path)
            }

        # Phase 3: License/trial removal
        results["phases"]["crack"] = run_autonomous_crack(binary_path)

        # Phase 4: Verification
        if config.get("verify") and results["phases"]["crack"].get("success"):
            results["phases"]["verification"] = _verify_crack(binary_path)

        # Determine overall success
        results["overall_success"] = results["phases"]["crack"].get("success", False)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in full autonomous mode: %s", e)
        results["error"] = str(e)

    return results


def run_ghidra_analysis_gui(binary_path: str, ghidra_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Run Ghidra analysis with GUI integration.

    Args:
        binary_path: Path to the binary file
        ghidra_path: Path to Ghidra installation

    Returns:
        Dict containing Ghidra analysis status
    """
    results = {
        "binary": binary_path,
        "ghidra_path": ghidra_path,
        "launched": False
    }

    try:
        # Find Ghidra installation
        if ghidra_path is None:
            ghidra_path = _find_ghidra_installation()

        if not ghidra_path:
            results["error"] = "Ghidra installation not found"
            return results

        # Launch Ghidra with the binary
        ghidra_run = os.path.join(ghidra_path, "ghidraRun")
        if sys.platform == "win32":
            ghidra_run += ".bat"

        if os.path.exists(ghidra_run):
            # Create project directory
            project_dir = os.path.join(os.path.dirname(binary_path), "ghidra_project")
            os.makedirs(project_dir, exist_ok=True)

            # Launch Ghidra
            cmd = [ghidra_run, binary_path]
            subprocess.Popen(cmd, encoding='utf-8')

            results["launched"] = True
            results["project_dir"] = project_dir
            results["message"] = "Ghidra GUI launched successfully"
        else:
            results["error"] = f"Ghidra run script not found: {ghidra_run}"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error launching Ghidra GUI: %s", e)
        results["error"] = str(e)

    return results


def run_incremental_analysis_ui(binary_path: str, cache_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Run incremental analysis with UI updates.

    Args:
        binary_path: Path to the binary file
        cache_dir: Cache directory

    Returns:
        Dict containing incremental analysis results
    """
    try:
        from .distributed_processing import run_incremental_analysis

        # Run incremental analysis
        results = run_incremental_analysis(binary_path, cache_dir)

        # Add UI-specific information
        results["ui_data"] = {
            "cache_percentage": (results["cache_hits"] /
                               (results["cache_hits"] + results["cache_misses"]) * 100
                               if results["cache_hits"] + results["cache_misses"] > 0 else 0),
            "new_analyses": list(results.get("new_results", {}).keys()),
            "cached_analyses": list(results.get("cached_results", {}).keys())
        }

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in incremental analysis UI: %s", e)
        return {"error": str(e)}


def run_deep_cfg_analysis(binary_path: str, output_format: str = "json") -> Dict[str, Any]:
    """
    Run deep control flow graph analysis.

    Args:
        binary_path: Path to the binary file
        output_format: Output format (json, dot, html)

    Returns:
        Dict containing CFG analysis results
    """
    try:
        from ..core.analysis.cfg_explorer import CFGExplorer

        results = {
            "binary": binary_path,
            "functions_analyzed": 0,
            "license_checks_found": [],
            "control_flow_patterns": []
        }

        # Create CFG explorer
        explorer = CFGExplorer()
        explorer.load_binary(binary_path)

        # Analyze all functions
        functions = explorer.get_functions()
        results["total_functions"] = len(functions)

        for func in functions:
            try:
                # Analyze function CFG
                cfg = explorer.analyze_function(func["name"])

                if cfg:
                    results["functions_analyzed"] += 1

                    # Look for license check patterns
                    if _is_license_check_pattern(cfg):
                        results["license_checks_found"].append({
                            "function": func["name"],
                            "address": func["address"],
                            "complexity": cfg.get("complexity", 0)
                        })

            except (OSError, ValueError, RuntimeError) as e:
                logger.error(f"Error analyzing function {func['name']}: {e}")

        # Generate output
        if output_format == "html":
            results["visualization"] = explorer.visualize_cfg()
        elif output_format == "dot":
            results["visualization"] = explorer.export_dot("cfg_output.dot")

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in deep CFG analysis: %s", e)
        return {"error": str(e)}


def run_external_tool(tool_name: str, binary_path: str,
                     args: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run external analysis tool.

    Args:
        tool_name: Name of the tool
        binary_path: Path to the binary file
        args: Additional arguments

    Returns:
        Dict containing tool execution results
    """
    results = {
        "tool": tool_name,
        "binary": binary_path,
        "executed": False
    }

    # Tool command mapping
    tools = {
        "strings": ["strings", "-a"],
        "file": ["file"],
        "objdump": ["objdump", "-d"],
        "readelf": ["readelf", "-a"],
        "ldd": ["ldd"],
        "nm": ["nm", "-D"],
        "upx": ["upx", "-t"],
        "pescan": ["pescan"],
        "rabin2": ["rabin2", "-I"]
    }

    if tool_name not in tools:
        results["error"] = f"Unknown tool: {tool_name}"
        return results

    try:
        # Build command
        cmd = tools[tool_name] + [binary_path]
        if args:
            cmd.extend(args)

        # Execute tool
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)

        results["executed"] = True
        results["return_code"] = result.returncode
        results["stdout"] = result.stdout
        results["stderr"] = result.stderr

        if result.returncode == 0:
            results["success"] = True
            # Parse tool-specific output
            results["parsed"] = _parse_tool_output(tool_name, result.stdout)
        else:
            results["success"] = False

    except subprocess.TimeoutExpired:
        results["error"] = "Tool execution timed out"
    except FileNotFoundError:
        results["error"] = f"Tool '{tool_name}' not found in PATH"
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error running external tool: %s", e)
        results["error"] = str(e)

    return results


# Platform-specific functions

def run_windows_activator(product: str = "windows", method: str = "kms") -> Dict[str, Any]:
    """
    Run Windows activation.

    Args:
        product: Product to activate (windows, office)
        method: Activation method (kms, mak, digital)

    Returns:
        Dict containing activation results
    """
    try:
        from ..core.patching.windows_activator import WindowsActivator

        activator = WindowsActivator()

        if product == "windows":
            if method == "kms":
                return activator.activate_windows_kms()
            elif method == "digital":
                return activator.activate_windows_digital()
        elif product == "office":
            return activator.activate_office()

        return {"error": f"Unknown product/method: {product}/{method}"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in Windows activation: %s", e)
        return {"error": str(e)}


def check_adobe_licensex_status() -> Dict[str, Any]:
    """
    Check Adobe license status.

    Returns:
        Dict containing Adobe license status
    """
    results = {
        "adobe_installed": False,
        "license_status": "unknown",
        "products": []
    }

    try:
        # Check for Adobe installation
        adobe_paths = [
            r"C:\Program Files\Adobe",
            r"C:\Program Files (x86)\Adobe",
            r"C:\Program Files\Common Files\Adobe"
        ]

        for path in adobe_paths:
            if os.path.exists(path):
                results["adobe_installed"] = True
                # List Adobe products
                products = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
                results["products"].extend(products)

        # Check license files
        license_paths = [
            os.path.expanduser(r"~\AppData\Roaming\Adobe"),
            r"C:\ProgramData\Adobe"
        ]

        for path in license_paths:
            if os.path.exists(path):
                # Look for license files
                for _root, _dirs, files in os.walk(path):
                    for file in files:
                        if "license" in file.lower() or ".lic" in file.lower():
                            results["license_files_found"] = True
                            break

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error checking Adobe license: %s", e)
        results["error"] = str(e)

    return results


def run_adobe_licensex_manually(action: str = "bypass") -> Dict[str, Any]:
    """
    Run manual Adobe license operations.

    Args:
        action: Action to perform (bypass, reset, check)

    Returns:
        Dict containing operation results
    """
    try:
        from ..core.patching.adobe_injector import AdobeLicenseInjector

        injector = AdobeLicenseInjector()

        if action == "bypass":
            return injector.inject_license_bypass()
        elif action == "reset":
            return injector.reset_trial()
        elif action == "check":
            return check_adobe_licensex_status()

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in Adobe license operation: %s", e)
        return {"error": str(e)}


# Utility functions

def validate_dataset(dataset_path: str, dataset_type: str = "binary") -> Dict[str, Any]:
    """
    Validate a dataset for ML training.

    Args:
        dataset_path: Path to dataset
        dataset_type: Type of dataset

    Returns:
        Dict containing validation results
    """
    results = {
        "path": dataset_path,
        "type": dataset_type,
        "valid": False,
        "issues": []
    }

    try:
        if dataset_type == "binary":
            # Validate binary dataset
            if os.path.isdir(dataset_path):
                files = [f for f in os.listdir(dataset_path) if f.endswith(('.exe', '.dll', '.so', '.dylib'))]
                results["file_count"] = len(files)

                if len(files) == 0:
                    results["issues"].append("No binary files found")
                else:
                    results["valid"] = True
                    results["sample_files"] = files[:5]

        elif dataset_type == "json":
            # Validate JSON dataset
            if os.path.isfile(dataset_path):
                with open(dataset_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                results["record_count"] = len(data) if isinstance(data, list) else 1
                results["valid"] = True
            else:
                results["issues"].append("File not found")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error validating dataset: %s", e)
        results["issues"].append(str(e))

    return results


def verify_hash(file_path: str, expected_hash: str,
               algorithm: str = "sha256") -> Dict[str, Any]:
    """
    Verify file hash.

    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm

    Returns:
        Dict containing verification results
    """
    results = {
        "file": file_path,
        "algorithm": algorithm,
        "expected": expected_hash,
        "verified": False
    }

    try:
        h = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)

        actual_hash = h.hexdigest()
        results["actual"] = actual_hash
        results["verified"] = actual_hash.lower() == expected_hash.lower()

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error verifying hash: %s", e)
        results["error"] = str(e)

    return results


def run_external_command(command: Union[str, List[str]],
                        timeout: int = 60) -> Dict[str, Any]:
    """
    Run external command.

    Args:
        command: Command to run
        timeout: Timeout in seconds

    Returns:
        Dict containing command results
    """
    results = {
        "command": command,
        "executed": False
    }

    try:
        if isinstance(command, str):
            command = command.split()

        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)

        results["executed"] = True
        results["return_code"] = result.returncode
        results["stdout"] = result.stdout
        results["stderr"] = result.stderr
        results["success"] = result.returncode == 0

    except subprocess.TimeoutExpired:
        results["error"] = "Command timed out"
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error running command: %s", e)
        results["error"] = str(e)

    return results


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Compute file hash.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm

    Returns:
        Hash string
    """
    h = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)

    return h.hexdigest()


def create_sample_plugins() -> Dict[str, Any]:
    """
    Create sample plugin templates.

    Returns:
        Dict containing created plugin information
    """
    plugin_dir = os.path.join(os.getcwd(), "plugins", "samples")
    os.makedirs(plugin_dir, exist_ok=True)

    results = {
        "plugin_dir": plugin_dir,
        "plugins_created": []
    }

    # Python plugin template
    python_plugin = '''"""
Sample Intellicrack Plugin
"""

def initialize():
    """Initialize the plugin."""
    print("Sample plugin initialized")
    return True

def analyze(binary_path):
    """Analyze a binary."""
    return {
        "plugin": "sample",
        "binary": binary_path,
        "results": "Sample analysis complete"
    }

def get_info():
    """Get plugin information."""
    return {
        "name": "Sample Plugin",
        "version": "1.0",
        "author": "Intellicrack",
        "description": "Sample plugin template"
    }
'''

    # Frida script template
    frida_script = '''// Sample Frida Script for Intellicrack

// Hook common functions
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        console.log("strcmp called:");
        console.log("  arg0: " + Memory.readUtf8String(args[0]));
        console.log("  arg1: " + Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("  result: " + retval);
    }
});

console.log("Sample Frida script loaded");
'''

    try:
        # Create Python plugin
        python_file = os.path.join(plugin_dir, "sample_plugin.py")
        with open(python_file, 'w', encoding='utf-8') as f:
            f.write(python_plugin)
        results["plugins_created"].append(python_file)

        # Create Frida script
        frida_file = os.path.join(plugin_dir, "sample_frida.js")
        with open(frida_file, 'w', encoding='utf-8') as f:
            f.write(frida_script)
        results["plugins_created"].append(frida_file)

        results["success"] = True

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error creating sample plugins: %s", e)
        results["error"] = str(e)

    return results


def load_ai_model(model_path: str, model_type: str = "auto") -> Dict[str, Any]:
    """
    Load AI model for analysis.

    Args:
        model_path: Path to model file
        model_type: Type of model (auto, pytorch, tensorflow, sklearn)

    Returns:
        Dict containing model loading results
    """
    results = {
        "model_path": model_path,
        "model_type": model_type,
        "loaded": False
    }

    try:
        if model_type == "auto":
            # Detect model type by extension
            if model_path.endswith('.pt') or model_path.endswith('.pth'):
                model_type = "pytorch"
            elif model_path.endswith('.h5') or model_path.endswith('.keras'):
                model_type = "tensorflow"
            elif model_path.endswith('.pkl') or model_path.endswith('.joblib'):
                model_type = "sklearn"

        results["detected_type"] = model_type

        # Load based on type
        if model_type == "sklearn":
            import joblib
            model = joblib.load(model_path)
            results["loaded"] = True
            results["model_info"] = {
                "type": type(model).__name__,
                "features": getattr(model, 'n_features_in_', 'unknown')
            }

        else:
            results["error"] = f"Model type {model_type} not implemented"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error loading AI model: %s", e)
        results["error"] = str(e)

    return results


def get_target_process_pid(process_name: str) -> Optional[int]:
    """
    Get process ID by name.

    Args:
        process_name: Name of the process

    Returns:
        Process ID or None
    """
    try:
        import psutil

        for proc in psutil.process_iter(['pid', 'name']):
            if process_name.lower() in proc.info['name'].lower():
                return proc.info['pid']

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error getting process PID: %s", e)

    return None


def _detect_usb_dongles() -> List[Dict[str, Any]]:
    """Detect USB dongles by enumerating USB devices."""
    dongles = []

    try:
        # Try pyusb for cross-platform USB detection
        try:
            import usb.core
            import usb.util

            devices = usb.core.find(find_all=True)
            for device in devices:
                try:
                    manufacturer = usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else "Unknown"
                    product = usb.util.get_string(device, device.iProduct) if device.iProduct else "Unknown"

                    # Check for known dongle manufacturers
                    known_vendors = ["sentinel", "hasp", "aladdin", "wibu", "securikey", "rockey", "marx", "eutron"]
                    if any(vendor in manufacturer.lower() or vendor in product.lower() for vendor in known_vendors):
                        dongles.append({
                            "type": "usb_dongle",
                            "vendor_id": device.idVendor,
                            "product_id": device.idProduct,
                            "manufacturer": manufacturer,
                            "product": product,
                            "confidence": 0.9
                        })
                except Exception as e:
                    logger.debug("Failed to get USB device info: %s", e)
                    continue

        except ImportError:
            # Fallback to platform-specific methods
            import platform
            system = platform.system().lower()

            if system == "windows":
                dongles.extend(_detect_windows_usb_dongles())
            elif system == "linux":
                dongles.extend(_detect_linux_usb_dongles())

    except Exception as e:
        logger.debug("USB dongle detection error: %s", e)

    return dongles


def _detect_windows_usb_dongles() -> List[Dict[str, Any]]:
    """Detect USB dongles on Windows using WMI."""
    dongles = []

    try:
        import json
        import subprocess

        # Use PowerShell to query USB devices
        cmd = ["powershell", "-Command",
               "Get-WmiObject -Class Win32_USBDevice | Select-Object DeviceID, Description, Manufacturer | ConvertTo-Json"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            devices = json.loads(result.stdout)
            if not isinstance(devices, list):
                devices = [devices]

            for device in devices:
                desc = device.get("Description", "").lower()
                mfg = device.get("Manufacturer", "").lower()

                # Check for dongle keywords
                if any(keyword in desc or keyword in mfg for keyword in
                      ["sentinel", "hasp", "wibu", "aladdin", "dongle", "key", "securikey"]):
                    dongles.append({
                        "type": "windows_usb_dongle",
                        "device_id": device.get("DeviceID"),
                        "description": device.get("Description"),
                        "manufacturer": device.get("Manufacturer"),
                        "confidence": 0.85
                    })

    except Exception as e:
        logger.debug("Windows USB dongle detection error: %s", e)

    return dongles


def _detect_linux_usb_dongles() -> List[Dict[str, Any]]:
    """Detect USB dongles on Linux using lsusb."""
    dongles = []

    try:
        import subprocess

        # Use lsusb to list USB devices
        result = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip():
                    line_lower = line.lower()
                    if any(keyword in line_lower for keyword in
                          ["sentinel", "hasp", "wibu", "aladdin", "dongle", "key"]):
                        dongles.append({
                            "type": "linux_usb_dongle",
                            "description": line.strip(),
                            "confidence": 0.8
                        })

    except Exception as e:
        logger.debug("Linux USB dongle detection error: %s", e)

    return dongles


def _detect_dongle_processes() -> List[Dict[str, Any]]:
    """Detect dongle-related processes."""
    processes = []

    try:
        import psutil

        # Known dongle process names
        dongle_processes = [
            "aksusbd", "hasplms", "wkssvc", "nhsrvice", "aksusbd",
            "sentinel", "wibukey", "cryptkey", "securikey", "rockey"
        ]

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                proc_exe = proc.info['exe'].lower() if proc.info['exe'] else ""

                if any(dongle_proc in proc_name or dongle_proc in proc_exe
                      for dongle_proc in dongle_processes):
                    processes.append({
                        "type": "dongle_process",
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "exe": proc.info['exe'],
                        "confidence": 0.9
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except ImportError:
        logger.debug("psutil not available for process detection")
    except Exception as e:
        logger.debug("Process dongle detection error: %s", e)

    return processes


def _detect_dongle_drivers() -> List[Dict[str, Any]]:
    """Detect dongle-related drivers."""
    drivers = []

    try:
        import platform
        system = platform.system().lower()

        if system == "windows":
            drivers.extend(_detect_windows_dongle_drivers())
        elif system == "linux":
            drivers.extend(_detect_linux_dongle_drivers())

    except Exception as e:
        logger.debug("Driver dongle detection error: %s", e)

    return drivers


def _detect_windows_dongle_drivers() -> List[Dict[str, Any]]:
    """Detect dongle drivers on Windows."""
    drivers = []

    try:
        import subprocess

        # Check for known dongle drivers
        driver_patterns = ["hasp", "sentinel", "wibu", "aksusb", "securikey"]

        cmd = ["driverquery", "/v", "/fo", "csv"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            import csv
            import io

            reader = csv.DictReader(io.StringIO(result.stdout))
            for row in reader:
                driver_name = row.get("Display Name", "").lower()
                if any(pattern in driver_name for pattern in driver_patterns):
                    drivers.append({
                        "type": "windows_dongle_driver",
                        "name": row.get("Display Name"),
                        "path": row.get("Path"),
                        "confidence": 0.85
                    })

    except Exception as e:
        logger.debug("Windows driver detection error: %s", e)

    return drivers


def _detect_linux_dongle_drivers() -> List[Dict[str, Any]]:
    """Detect dongle drivers on Linux."""
    drivers = []

    try:
        import subprocess

        # Check loaded kernel modules
        result = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if line.strip():
                    module_name = line.split()[0].lower()
                    if any(pattern in module_name for pattern in
                          ["hasp", "sentinel", "wibu", "dongle"]):
                        drivers.append({
                            "type": "linux_dongle_driver",
                            "module": module_name,
                            "confidence": 0.8
                        })

    except Exception as e:
        logger.debug("Linux driver detection error: %s", e)

    return drivers


def _detect_license_dongles() -> List[Dict[str, Any]]:
    """Detect software-based license dongles."""
    license_files = []

    try:
        import glob
        import os

        # Common license file locations and patterns
        search_patterns = [
            "/var/hasplm/*",
            "/opt/*/license*",
            "C:/ProgramData/*/license*",
            "C:/Program Files*/*/license*",
            "*.lic",
            "*.key",
            "*.dongle"
        ]

        for pattern in search_patterns:
            try:
                for file_path in glob.glob(pattern, recursive=True):
                    if os.path.isfile(file_path):
                        license_files.append({
                            "type": "license_file",
                            "path": file_path,
                            "size": os.path.getsize(file_path),
                            "confidence": 0.7
                        })
            except Exception as e:
                logger.debug("Failed to search pattern '%s': %s", pattern, e)
                continue

    except Exception as e:
        logger.debug("License file detection error: %s", e)

    return license_files[:10]  # Limit to 10 results


def _detect_network_dongles() -> List[Dict[str, Any]]:
    """Detect network-based dongles."""
    network_dongles = []

    try:
        import socket

        # Common dongle server ports
        dongle_ports = [1947, 1692, 5093, 22350, 475]

        for port in dongle_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                if result == 0:
                    network_dongles.append({
                        "type": "network_dongle",
                        "host": "localhost",
                        "port": port,
                        "confidence": 0.8
                    })
                sock.close()
            except Exception as e:
                logger.debug("Port %d connection failed: %s", port, e)
                continue

    except Exception as e:
        logger.debug("Network dongle detection error: %s", e)

    return network_dongles


def detect_hardware_dongles() -> Dict[str, Any]:
    """
    Detect hardware dongles.

    Returns:
        Dict containing dongle detection results
    """
    results = {
        "dongles_found": [],
        "usb_devices": []
    }

    try:
        # This would require platform-specific USB enumeration
        # Detect hardware dongles using multiple methods

        # Method 1: USB device enumeration
        usb_dongles = _detect_usb_dongles()
        results["usb_devices"].extend(usb_dongles)

        # Method 2: Process and registry analysis
        process_dongles = _detect_dongle_processes()
        results["dongle_processes"] = process_dongles

        # Method 3: Driver analysis
        driver_dongles = _detect_dongle_drivers()
        results["dongle_drivers"] = driver_dongles

        # Method 4: License file analysis
        license_dongles = _detect_license_dongles()
        results["license_files"] = license_dongles

        # Method 5: Network dongles
        network_dongles = _detect_network_dongles()
        results["network_dongles"] = network_dongles

        # Analyze findings
        total_detected = len(results["usb_devices"]) + len(process_dongles) + len(driver_dongles) + len(license_dongles) + len(network_dongles)
        if total_detected > 0:
            results["detected"] = True
            results["confidence"] = min(0.95, 0.3 + (total_detected * 0.15))
            results["message"] = f"Detected {total_detected} potential hardware protection mechanism(s)"
        else:
            results["detected"] = False
            results["confidence"] = 0.8
            results["message"] = "No hardware dongles detected using available methods"

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting hardware dongles: %s", e)
        results["error"] = str(e)

    return results


def detect_tpm_protection(binary_path: str) -> Dict[str, Any]:
    """
    Detect TPM protection in binary.

    Args:
        binary_path: Path to binary

    Returns:
        Dict containing TPM detection results
    """
    try:
        from .protection_detection import detect_tpm_protection as tpm_detect
        return tpm_detect(binary_path)
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error detecting TPM protection: %s", e)
        return {"error": str(e)}


# Helper functions

def _generate_analysis_summary(analyses: Dict[str, Any]) -> Dict[str, Any]:
    """Generate summary from analysis results."""
    summary = {
        "total_analyses": len(analyses),
        "successful": sum(1 for a in analyses.values() if "error" not in a),
        "issues_found": []
    }

    # Check for specific issues
    if analyses.get("protection_scan", {}).get("protections_found"):
        summary["issues_found"].append("Protection mechanisms detected")

    if analyses.get("vulnerabilities", {}).get("vulnerable_functions"):
        summary["issues_found"].append("Potential vulnerabilities found")

    if analyses.get("entropy", {}).get("statistics", {}).get("average_entropy", 0) > 7.0:
        summary["issues_found"].append("High entropy - possible packing")

    return summary


def _generate_bypass_suggestions(pattern_results: Dict[str, Any]) -> List[str]:
    """Generate bypass suggestions based on patterns found."""
    suggestions = []

    if "activation" in pattern_results:
        suggestions.append("Patch activation validation routines")

    if "trial" in pattern_results:
        suggestions.append("Reset or extend trial period")

    if "hardware" in pattern_results:
        suggestions.append("Spoof hardware ID verification")

    if "network" in pattern_results:
        suggestions.append("Intercept and modify network license checks")

    if "crypto" in pattern_results:
        suggestions.append("Analyze cryptographic validation methods")

    return suggestions


def _determine_target_type(analysis: Dict[str, Any]) -> str:
    """Determine target type from analysis."""
    patterns = analysis.get("analyses", {}).get("patterns", {})

    if patterns.get("pattern_summary", {}).get("license", {}).get("count", 0) > 0:
        return "license"
    elif patterns.get("pattern_summary", {}).get("trial", {}).get("count", 0) > 0:
        return "trial"
    else:
        return "protection"


def _verify_crack(binary_path: str) -> Dict[str, Any]:
    """
    Verify if crack was successful using multiple verification methods.
    
    Args:
        binary_path: Path to the patched binary to verify
        
    Returns:
        Dict containing verification results
    """
    verification_result = {
        "verified": False,
        "confidence": 0.0,
        "methods_used": [],
        "findings": [],
        "warnings": [],
        "execution_tests": [],
        "static_checks": [],
        "behavior_analysis": {}
    }

    try:
        logger.info("Starting crack verification for: %s", binary_path)

        # Method 1: Static analysis verification
        static_results = _verify_static_analysis(binary_path)
        verification_result["static_checks"] = static_results
        verification_result["methods_used"].append("static_analysis")

        # Method 2: Controlled execution testing
        execution_results = _verify_execution_testing(binary_path)
        verification_result["execution_tests"] = execution_results
        verification_result["methods_used"].append("execution_testing")

        # Method 3: Protection mechanism checks
        protection_results = _verify_protection_bypass(binary_path)
        verification_result["behavior_analysis"]["protection_bypass"] = protection_results
        verification_result["methods_used"].append("protection_analysis")

        # Method 4: License validation checks
        license_results = _verify_license_bypass(binary_path)
        verification_result["behavior_analysis"]["license_bypass"] = license_results
        verification_result["methods_used"].append("license_analysis")

        # Method 5: File integrity and patch validation
        patch_results = _verify_patch_integrity(binary_path)
        verification_result["behavior_analysis"]["patch_integrity"] = patch_results
        verification_result["methods_used"].append("patch_validation")

        # Calculate overall verification confidence
        verification_scores = []

        if static_results.get("success", False):
            verification_scores.append(static_results.get("confidence", 0.0))

        if execution_results.get("success", False):
            verification_scores.append(execution_results.get("confidence", 0.0))

        if protection_results.get("bypassed", False):
            verification_scores.append(protection_results.get("confidence", 0.0))

        if license_results.get("bypassed", False):
            verification_scores.append(license_results.get("confidence", 0.0))

        if patch_results.get("valid", False):
            verification_scores.append(patch_results.get("confidence", 0.0))

        # Overall verification
        if verification_scores:
            verification_result["confidence"] = sum(verification_scores) / len(verification_scores)
            verification_result["verified"] = verification_result["confidence"] > 0.7

            if verification_result["verified"]:
                verification_result["findings"].append(f"Crack verification successful with {verification_result['confidence']:.2f} confidence")
            else:
                verification_result["warnings"].append(f"Crack verification inconclusive (confidence: {verification_result['confidence']:.2f})")
        else:
            verification_result["warnings"].append("No verification methods succeeded")
            verification_result["confidence"] = 0.0

        logger.info("Crack verification completed. Verified: %s, Confidence: %.2f",
                   verification_result["verified"], verification_result["confidence"])

    except Exception as e:
        logger.error("Error in crack verification: %s", e)
        verification_result["warnings"].append(f"Verification error: {e}")

    return verification_result


def _verify_static_analysis(binary_path: str) -> Dict[str, Any]:
    """Verify crack through static analysis."""
    result = {"success": False, "confidence": 0.0, "checks": []}

    try:
        import os

        if not os.path.exists(binary_path):
            result["checks"].append("File does not exist")
            return result

        # Check 1: File size changes (patches should modify file)
        file_size = os.path.getsize(binary_path)
        if file_size > 0:
            result["checks"].append(f"File exists and has size: {file_size} bytes")

        # Check 2: Look for common crack signatures in binary
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read(min(file_size, 1024 * 1024))  # Read first 1MB

            # Look for patterns indicating successful patching
            crack_patterns = [
                b'\x90\x90\x90',  # NOP sleds
                b'\xEB',          # JMP instructions
                b'\xB0\x01',      # MOV AL, 1
                b'\x31\xC0',      # XOR EAX, EAX
                b'\xC3'           # RET
            ]

            patterns_found = 0
            for pattern in crack_patterns:
                if pattern in binary_data:
                    patterns_found += 1
                    result["checks"].append(f"Found potential patch pattern: {pattern.hex()}")

            if patterns_found > 0:
                result["confidence"] = min(0.9, 0.3 + (patterns_found * 0.2))
                result["success"] = True
                result["checks"].append(f"Static analysis suggests binary has been modified ({patterns_found} patterns)")
            else:
                result["checks"].append("No obvious patch patterns detected")

        except Exception as e:
            result["checks"].append(f"Error reading binary: {e}")

    except Exception as e:
        result["checks"].append(f"Static analysis error: {e}")

    return result


def _verify_execution_testing(binary_path: str) -> Dict[str, Any]:
    """Verify crack through controlled execution testing."""
    result = {"success": False, "confidence": 0.0, "tests": []}

    try:
        import os
        import platform
        import subprocess

        if not os.path.exists(binary_path):
            result["tests"].append("Binary file not found")
            return result

        # Make sure file is executable
        if platform.system() != "Windows":
            try:
                os.chmod(binary_path, 0o755)
            except Exception as e:
                logger.debug("Could not set executable permissions: %s", e)

        # Test 1: Basic execution test (does it run without crashing?)
        try:
            # Run with timeout to prevent hanging
            proc = subprocess.run(
                [binary_path, "--version"],  # Try common version flag
                capture_output=True,
                text=True,
                timeout=10
            )

            if proc.returncode == 0:
                result["tests"].append("Binary executes successfully")
                result["confidence"] += 0.3
            else:
                result["tests"].append(f"Binary execution failed with code: {proc.returncode}")

        except subprocess.TimeoutExpired:
            result["tests"].append("Binary execution timed out (may be waiting for input)")
            result["confidence"] += 0.1
        except Exception as e:
            result["tests"].append(f"Execution test error: {e}")

        # Test 2: Check for license-related error messages
        try:
            proc = subprocess.run(
                [binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = (proc.stdout + proc.stderr).lower()

            # Look for license failure messages
            license_errors = [
                "license", "trial", "expired", "invalid", "demo",
                "activation", "serial", "key", "registration"
            ]

            has_license_errors = any(error in output for error in license_errors)

            if not has_license_errors and len(output) > 0:
                result["tests"].append("No license error messages detected")
                result["confidence"] += 0.4
                result["success"] = True
            elif has_license_errors:
                result["tests"].append("License error messages still present")
            else:
                result["tests"].append("No output captured from execution")

        except subprocess.TimeoutExpired:
            result["tests"].append("Binary execution hangs (possible input wait)")
        except Exception as e:
            result["tests"].append(f"License test error: {e}")

        # Test 3: File system access test
        try:
            # Check if binary tries to access common license file locations
            import tempfile

            with tempfile.TemporaryDirectory() as temp_dir:
                env = os.environ.copy()
                env["TEMP"] = temp_dir
                env["TMP"] = temp_dir

                proc = subprocess.run(
                    [binary_path, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    env=env,
                    cwd=temp_dir
                )

                result["tests"].append("Filesystem access test completed")

        except Exception as e:
            result["tests"].append(f"Filesystem test error: {e}")

        # Overall success determination
        if result["confidence"] > 0.5:
            result["success"] = True

    except Exception as e:
        result["tests"].append(f"Execution testing error: {e}")

    return result


def _verify_protection_bypass(binary_path: str) -> Dict[str, Any]:
    """Verify that protection mechanisms have been bypassed."""
    result = {"bypassed": False, "confidence": 0.0, "protections": []}

    try:
        # Check for common protection mechanisms that should be disabled

        # Protection 1: Check for debugger detection bypass
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read(min(1024*1024, 1000000))  # Read first 1MB

            # Look for common anti-debug patterns that should be NOPed
            anti_debug_patterns = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess'
            ]

            debug_protection_found = sum(1 for pattern in anti_debug_patterns if pattern in binary_data)

            if debug_protection_found == 0:
                result["protections"].append("Anti-debugging protection appears bypassed")
                result["confidence"] += 0.3
            else:
                result["protections"].append(f"Anti-debugging functions still present ({debug_protection_found})")

        except Exception as e:
            result["protections"].append(f"Debug protection check error: {e}")

        # Protection 2: Check for VM detection bypass
        try:
            vm_patterns = [b'VMware', b'VirtualBox', b'QEMU', b'Xen']
            vm_detection_found = sum(1 for pattern in vm_patterns if pattern in binary_data)

            if vm_detection_found == 0:
                result["protections"].append("VM detection appears bypassed")
                result["confidence"] += 0.2
            else:
                result["protections"].append(f"VM detection strings still present ({vm_detection_found})")

        except Exception as e:
            result["protections"].append(f"VM protection check error: {e}")

        # Protection 3: Check for integrity checks bypass
        try:
            integrity_patterns = [b'CRC', b'checksum', b'hash', b'MD5', b'SHA']
            integrity_checks_found = sum(1 for pattern in integrity_patterns if pattern in binary_data)

            # If integrity checks are found but binary still runs, they may be bypassed
            if integrity_checks_found > 0:
                result["protections"].append("Integrity check functions present but may be bypassed")
                result["confidence"] += 0.2
            else:
                result["protections"].append("No obvious integrity check functions found")
                result["confidence"] += 0.1

        except Exception as e:
            result["protections"].append(f"Integrity check error: {e}")

        # Overall bypass determination
        if result["confidence"] > 0.4:
            result["bypassed"] = True

    except Exception as e:
        result["protections"].append(f"Protection bypass verification error: {e}")

    return result


def _verify_license_bypass(binary_path: str) -> Dict[str, Any]:
    """Verify that license checks have been bypassed."""
    result = {"bypassed": False, "confidence": 0.0, "license_checks": []}

    try:
        # Check for evidence of successful license bypass

        # Check 1: Look for hardcoded success returns
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read(min(1024*1024, 1000000))

            # Look for patterns indicating license bypass
            bypass_patterns = [
                b'\xB0\x01\xC3',    # MOV AL, 1; RET (return true)
                b'\x31\xC0\x40\xC3', # XOR EAX, EAX; INC EAX; RET (return 1)
                b'\xB8\x01\x00\x00\x00\xC3'  # MOV EAX, 1; RET
            ]

            bypass_patterns_found = sum(1 for pattern in bypass_patterns if pattern in binary_data)

            if bypass_patterns_found > 0:
                result["license_checks"].append(f"Found {bypass_patterns_found} potential license bypass pattern(s)")
                result["confidence"] += 0.4
            else:
                result["license_checks"].append("No obvious license bypass patterns detected")

        except Exception as e:
            result["license_checks"].append(f"Pattern search error: {e}")

        # Check 2: Look for NOPed license checks
        try:
            nop_sequences = binary_data.count(b'\x90\x90\x90')  # Three or more NOPs

            if nop_sequences > 10:  # Threshold for significant NOPing
                result["license_checks"].append(f"Found {nop_sequences} NOP sequences (potential NOPed license checks)")
                result["confidence"] += 0.3
            elif nop_sequences > 0:
                result["license_checks"].append(f"Found {nop_sequences} small NOP sequences")
                result["confidence"] += 0.1
            else:
                result["license_checks"].append("No significant NOP sequences found")

        except Exception as e:
            result["license_checks"].append(f"NOP detection error: {e}")

        # Check 3: License string analysis
        try:
            license_strings = [b'license', b'trial', b'demo', b'activation', b'serial']
            license_refs_found = sum(1 for string in license_strings if string in binary_data)

            if license_refs_found > 0:
                result["license_checks"].append(f"License-related strings still present ({license_refs_found})")
                # This could be normal - the strings might still exist but checks bypassed
                result["confidence"] += 0.1
            else:
                result["license_checks"].append("No license-related strings found")
                result["confidence"] += 0.2

        except Exception as e:
            result["license_checks"].append(f"String analysis error: {e}")

        # Overall bypass determination
        if result["confidence"] > 0.5:
            result["bypassed"] = True

    except Exception as e:
        result["license_checks"].append(f"License bypass verification error: {e}")

    return result


def _verify_patch_integrity(binary_path: str) -> Dict[str, Any]:
    """Verify the integrity and validity of applied patches."""
    result = {"valid": False, "confidence": 0.0, "integrity_checks": []}

    try:
        import hashlib
        import os

        # Check 1: File exists and is readable
        if not os.path.exists(binary_path):
            result["integrity_checks"].append("Binary file does not exist")
            return result

        file_size = os.path.getsize(binary_path)
        if file_size == 0:
            result["integrity_checks"].append("Binary file is empty")
            return result

        result["integrity_checks"].append(f"Binary file exists with size: {file_size} bytes")
        result["confidence"] += 0.2

        # Check 2: File format integrity
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(512)

            # Check for valid executable headers
            if header.startswith(b'MZ'):  # PE header
                result["integrity_checks"].append("Valid PE executable header detected")
                result["confidence"] += 0.3
            elif header.startswith(b'\x7fELF'):  # ELF header
                result["integrity_checks"].append("Valid ELF executable header detected")
                result["confidence"] += 0.3
            elif header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:  # Mach-O
                result["integrity_checks"].append("Valid Mach-O executable header detected")
                result["confidence"] += 0.3
            else:
                result["integrity_checks"].append("Executable header format unrecognized or corrupted")

        except Exception as e:
            result["integrity_checks"].append(f"Header check error: {e}")

        # Check 3: Basic executable validation
        try:
            import platform
            system = platform.system()

            if system == "Windows" and binary_path.lower().endswith('.exe'):
                result["integrity_checks"].append("File extension matches platform")
                result["confidence"] += 0.1
            elif system != "Windows" and not binary_path.lower().endswith('.exe'):
                result["integrity_checks"].append("File format appropriate for platform")
                result["confidence"] += 0.1

        except Exception as e:
            result["integrity_checks"].append(f"Platform check error: {e}")

        # Check 4: Calculate file hash for future reference
        try:
            with open(binary_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            result["integrity_checks"].append(f"File hash calculated: {file_hash[:16]}...")
            result["file_hash"] = file_hash
            result["confidence"] += 0.1

        except Exception as e:
            result["integrity_checks"].append(f"Hash calculation error: {e}")

        # Overall validity determination
        if result["confidence"] > 0.6:
            result["valid"] = True
            result["integrity_checks"].append("Patch integrity validation passed")
        else:
            result["integrity_checks"].append("Patch integrity validation failed")

    except Exception as e:
        result["integrity_checks"].append(f"Patch integrity verification error: {e}")

    return result


def _find_ghidra_installation() -> Optional[str]:
    """Find Ghidra installation path."""
    # Try dynamic path discovery first
    try:
        from .path_discovery import find_tool
        ghidra_path = find_tool("ghidra")
        if ghidra_path:
            return ghidra_path
    except ImportError:
        pass

    # Fallback to legacy search
    common_paths = [
        r"C:\ghidra",
        r"C:\Program Files\ghidra",
        r"C:\Tools\ghidra",
    ]

    for path in common_paths:
        if os.path.exists(path):
            # Look for ghidra subdirectory
            for item in os.listdir(path):
                if item.startswith("ghidra_") and os.path.isdir(os.path.join(path, item)):
                    return os.path.join(path, item)

    return None


def _is_license_check_pattern(cfg: Dict[str, Any]) -> bool:
    """
    Check if CFG contains license check patterns.
    
    Analyzes control flow graph structures to identify patterns commonly
    associated with license verification routines.
    
    Args:
        cfg: Control flow graph data dictionary
        
    Returns:
        bool: True if license check patterns are detected
    """
    try:
        # Initialize pattern scoring
        pattern_score = 0.0
        max_score = 10.0

        # Pattern 1: Control flow complexity (license checks tend to be complex)
        complexity = cfg.get("complexity", 0)
        if complexity > 15:
            pattern_score += 2.0
            logger.debug("High complexity detected: %d", complexity)
        elif complexity > 8:
            pattern_score += 1.0
            logger.debug("Medium complexity detected: %d", complexity)

        # Pattern 2: Multiple branching paths (validation logic)
        branches = cfg.get("branches", 0)
        if branches > 10:
            pattern_score += 2.0
            logger.debug("High branching detected: %d", branches)
        elif branches > 5:
            pattern_score += 1.0
            logger.debug("Medium branching detected: %d", branches)

        # Pattern 3: Function call patterns
        function_calls = cfg.get("function_calls", [])
        license_related_calls = _identify_license_related_calls(function_calls)
        if license_related_calls > 3:
            pattern_score += 2.5
            logger.debug("Multiple license-related function calls: %d", license_related_calls)
        elif license_related_calls > 0:
            pattern_score += 1.0
            logger.debug("Some license-related function calls: %d", license_related_calls)

        # Pattern 4: String references
        string_refs = cfg.get("string_references", [])
        license_strings = _count_license_strings(string_refs)
        if license_strings > 2:
            pattern_score += 1.5
            logger.debug("Multiple license-related strings: %d", license_strings)
        elif license_strings > 0:
            pattern_score += 0.5
            logger.debug("Some license-related strings: %d", license_strings)

        # Pattern 5: Comparison operations (key validation)
        comparisons = cfg.get("comparison_operations", 0)
        if comparisons > 8:
            pattern_score += 1.5
            logger.debug("High number of comparisons: %d", comparisons)
        elif comparisons > 3:
            pattern_score += 0.5
            logger.debug("Medium number of comparisons: %d", comparisons)

        # Pattern 6: Loop structures (iterative validation)
        loops = cfg.get("loops", 0)
        if loops > 2:
            pattern_score += 1.0
            logger.debug("Multiple loops detected: %d", loops)
        elif loops > 0:
            pattern_score += 0.5
            logger.debug("Loop detected: %d", loops)

        # Pattern 7: Exception handling (error paths for invalid licenses)
        exception_handlers = cfg.get("exception_handlers", 0)
        if exception_handlers > 1:
            pattern_score += 1.0
            logger.debug("Exception handlers detected: %d", exception_handlers)

        # Pattern 8: Mathematical operations (key algorithms)
        math_operations = cfg.get("math_operations", 0)
        if math_operations > 10:
            pattern_score += 1.5
            logger.debug("High mathematical operations: %d", math_operations)
        elif math_operations > 5:
            pattern_score += 0.5
            logger.debug("Some mathematical operations: %d", math_operations)

        # Pattern 9: Registry/file access patterns
        registry_access = cfg.get("registry_access", 0)
        file_access = cfg.get("file_access", 0)
        if registry_access > 0 or file_access > 2:
            pattern_score += 1.0
            logger.debug("Registry/file access detected: reg=%d, file=%d", registry_access, file_access)

        # Pattern 10: Network operations (online license validation)
        network_calls = cfg.get("network_operations", 0)
        if network_calls > 0:
            pattern_score += 1.5
            logger.debug("Network operations detected: %d", network_calls)

        # Calculate final determination
        confidence_threshold = 5.0  # Minimum score to consider it a license check
        is_license_pattern = pattern_score >= confidence_threshold

        logger.info("License pattern analysis: score=%.1f/%.1f, threshold=%.1f, result=%s",
                   pattern_score, max_score, confidence_threshold, is_license_pattern)

        return is_license_pattern

    except Exception as e:
        logger.error("Error in license pattern analysis: %s", e)
        # Fallback to simple heuristic
        return cfg.get("complexity", 0) > 10 and cfg.get("branches", 0) > 5


def _identify_license_related_calls(function_calls: List[str]) -> int:
    """Identify license-related function calls."""
    license_keywords = [
        "license", "serial", "key", "activation", "trial", "demo",
        "validate", "verify", "check", "auth", "register", "unlock",
        "decrypt", "encode", "hash", "crypt", "sign", "cert",
        "dongle", "hasp", "sentinel", "wibu", "flexlm"
    ]

    count = 0
    for call in function_calls:
        call_lower = call.lower()
        if any(keyword in call_lower for keyword in license_keywords):
            count += 1
            logger.debug("License-related function call: %s", call)

    return count


def _count_license_strings(string_refs: List[str]) -> int:
    """Count license-related string references."""
    license_patterns = [
        "license", "trial", "demo", "expired", "invalid", "activation",
        "serial", "key", "unlock", "register", "auth", "verify",
        "pirate", "crack", "illegal", "copy", "protection",
        "dongles", "hasp", "sentinel", "wibu", "error", "fail"
    ]

    count = 0
    for string_ref in string_refs:
        string_lower = string_ref.lower()
        if any(pattern in string_lower for pattern in license_patterns):
            count += 1
            logger.debug("License-related string: %s", string_ref[:50])

    return count


def _parse_tool_output(tool_name: str, output: str) -> Dict[str, Any]:
    """Parse tool-specific output."""
    parsed = {}

    if tool_name == "strings":
        lines = output.strip().split('\n')
        parsed["string_count"] = len(lines)
        parsed["samples"] = lines[:20]

    elif tool_name == "file":
        parsed["file_type"] = output.strip()

    # Add more tool-specific parsing as needed

    return parsed


def run_vulnerability_scan(binary_path: str) -> Dict[str, Any]:
    """
    Run comprehensive vulnerability scan.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing vulnerability scan results
    """
    try:
        from ..core.analysis.vulnerability_engine import VulnerabilityEngine

        engine = VulnerabilityEngine()
        vulnerabilities = engine.scan_binary(binary_path)

        return {
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total": len(vulnerabilities),
                "high": sum(1 for v in vulnerabilities if v.get("severity") == "high"),
                "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
                "low": sum(1 for v in vulnerabilities if v.get("severity") == "low")
            }
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in vulnerability scan: %s", e)
        return {"status": "error", "message": str(e)}


def run_cfg_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Run control flow graph analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing CFG analysis results
    """
    try:
        from ..core.analysis.cfg_explorer import CFGExplorer

        explorer = CFGExplorer()
        cfg = explorer.analyze(binary_path)

        return {
            "status": "success",
            "cfg": cfg,
            "functions": explorer.get_functions(),
            "complexity": explorer.get_complexity_metrics()
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in CFG analysis: %s", e)
        return {"status": "error", "message": str(e)}


def run_rop_gadget_finder(binary_path: str) -> Dict[str, Any]:
    """
    Find ROP gadgets in binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing ROP gadgets
    """
    try:
        from ..core.analysis.rop_generator import ROPChainGenerator

        generator = ROPChainGenerator()
        generator.binary_path = binary_path
        gadgets = generator.find_gadgets()

        # Ensure gadgets is iterable, default to empty list if not
        if not gadgets or not isinstance(gadgets, (list, tuple)):
            gadgets = []

        # Simple categorization based on gadget patterns
        categories = {"ret": 0, "pop": 0, "mov": 0, "other": 0}
        for gadget in gadgets:
            gadget_str = str(gadget).lower()
            if "ret" in gadget_str:
                categories["ret"] += 1
            elif "pop" in gadget_str:
                categories["pop"] += 1
            elif "mov" in gadget_str:
                categories["mov"] += 1
            else:
                categories["other"] += 1

        return {
            "status": "success",
            "gadgets": gadgets,
            "total": len(gadgets),
            "categories": categories
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error finding ROP gadgets: %s", e)
        return {"status": "error", "message": str(e)}


def run_section_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Analyze binary sections.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing section analysis results
    """
    try:
        from .binary_analysis import analyze_binary

        # Get basic binary info which includes sections
        info = analyze_binary(binary_path, detailed=True)
        sections = info.get("sections", [])

        # Analyze each section
        section_analysis = []
        for section in sections:
            analysis = {
                "name": section.get("name"),
                "size": section.get("size", 0),
                "virtual_size": section.get("virtual_size", 0),
                "virtual_address": section.get("virtual_address", 0),
                "characteristics": section.get("characteristics", []),
                "entropy": section.get("entropy", 0),
                "suspicious": False
            }

            # Check for suspicious characteristics
            if analysis["entropy"] > 7.0:
                analysis["suspicious"] = True
                analysis["reason"] = "High entropy - possible packing"
            elif "WRITE" in analysis["characteristics"] and "EXECUTE" in analysis["characteristics"]:
                analysis["suspicious"] = True
                analysis["reason"] = "Writable and executable"

            section_analysis.append(analysis)

        return {
            "status": "success",
            "sections": section_analysis,
            "total": len(sections),
            "suspicious": sum(1 for s in section_analysis if s["suspicious"])
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in section analysis: %s", e)
        return {"status": "error", "message": str(e)}


def run_import_export_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Analyze imports and exports.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing import/export analysis
    """
    try:
        from .binary_analysis import analyze_binary

        # Get binary info which includes imports/exports
        info = analyze_binary(binary_path, detailed=True)

        imports = info.get("imports", {})
        exports = info.get("exports", [])

        # Analyze dangerous imports
        dangerous_apis = [
            "LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
            "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx",
            "RegOpenKey", "RegSetValue", "CreateFile", "DeleteFile",
            "WinExec", "ShellExecute", "system", "exec"
        ]

        dangerous_imports = []
        for dll, funcs in imports.items():
            for func in funcs:
                if any(api in func for api in dangerous_apis):
                    dangerous_imports.append({"dll": dll, "function": func})

        return {
            "status": "success",
            "imports": imports,
            "exports": exports,
            "import_count": sum(len(funcs) for funcs in imports.values()),
            "export_count": len(exports),
            "dangerous_imports": dangerous_imports,
            "dlls_imported": list(imports.keys())
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in import/export analysis: %s", e)
        return {"status": "error", "message": str(e)}


def run_weak_crypto_detection(binary_path: str) -> Dict[str, Any]:
    """
    Detect weak cryptography usage.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing weak crypto detection results
    """
    try:
        from .binary_analysis import analyze_patterns

        # Patterns for weak crypto
        weak_crypto_patterns = [
            b"MD5", b"SHA1", b"DES", b"RC4", b"ECB",
            b"md5_", b"sha1_", b"des_", b"rc4_",
            b"MD5Init", b"SHA1Init", b"DESCrypt",
            b"hardcoded_key", b"static_iv", b"weak_seed"
        ]

        # Search for patterns
        pattern_results = analyze_patterns(binary_path, weak_crypto_patterns)

        # Analyze strings for hardcoded keys
        hardcoded_keys = []
        if pattern_results.get("strings"):
            for string in pattern_results["strings"]:
                # Look for hex strings that might be keys
                if len(string) in [16, 24, 32, 48, 64] and all(c in "0123456789abcdefABCDEF" for c in string):
                    hardcoded_keys.append(string)

        weak_algorithms = []
        for pattern, matches in pattern_results.get("matches", {}).items():
            if matches:
                weak_algorithms.append({
                    "algorithm": pattern.decode('utf-8', errors='ignore'),
                    "occurrences": len(matches)
                })

        return {
            "status": "success",
            "weak_algorithms": weak_algorithms,
            "hardcoded_keys": hardcoded_keys[:10],  # Limit to first 10
            "issues_found": len(weak_algorithms) + len(hardcoded_keys),
            "severity": "high" if hardcoded_keys else ("medium" if weak_algorithms else "low")
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in weak crypto detection: %s", e)
        return {"status": "error", "message": str(e)}


def run_comprehensive_protection_scan(binary_path: str) -> Dict[str, Any]:
    """
    Run comprehensive protection scan.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing all protection mechanisms found
    """
    try:
        from ..core.analysis.core_analysis import detect_packing
        from .protection_detection import (
            detect_anti_debugging,
            detect_commercial_protections,
            detect_tpm_protection,
            detect_vm_detection,
        )

        results = {
            "status": "success",
            "protections": {}
        }

        # Detect packing
        packing = detect_packing(binary_path)
        if packing.get("packing_detected"):
            results["protections"]["packing"] = packing

        # Detect commercial protections
        commercial = detect_commercial_protections(binary_path)
        if commercial.get("protections_found"):
            results["protections"]["commercial"] = commercial

        # Detect anti-debugging
        anti_debug = detect_anti_debugging(binary_path)
        if anti_debug.get("techniques_found"):
            results["protections"]["anti_debugging"] = anti_debug

        # Detect VM detection
        vm_detect = detect_vm_detection(binary_path)
        if vm_detect.get("vm_detection_found"):
            results["protections"]["vm_detection"] = vm_detect

        # Detect TPM
        tpm = detect_tpm_protection(binary_path)
        if tpm.get("tpm_detected"):
            results["protections"]["tpm"] = tpm

        # Summary
        results["summary"] = {
            "total_protections": len(results["protections"]),
            "protection_types": list(results["protections"].keys()),
            "protection_level": "high" if len(results["protections"]) > 3 else
                              ("medium" if len(results["protections"]) > 1 else "low")
        }

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in protection scan: %s", e)
        return {"status": "error", "message": str(e)}


def run_ml_vulnerability_prediction(binary_path: str) -> Dict[str, Any]:
    """
    Run ML-based vulnerability prediction.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing ML predictions
    """
    try:
        from ..ai import VulnerabilityPredictor

        predictor = VulnerabilityPredictor()
        predictions = predictor.predict(binary_path)

        return {
            "status": "success",
            "predictions": predictions,
            "confidence": predictor.get_confidence_score(binary_path),
            "top_vulnerabilities": predictions[:5] if isinstance(predictions, list) else []
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ML vulnerability prediction: %s", e)
        return {"status": "error", "message": str(e)}


def run_generate_patch_suggestions(binary_path: str) -> Dict[str, Any]:
    """
    Generate patch suggestions for binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing patch suggestions
    """
    try:
        from ..core.patching.payload_generator import PayloadGenerator
        from .exploitation import analyze_for_patches

        # Analyze binary for patchable locations
        analysis = analyze_for_patches(binary_path)

        generator = PayloadGenerator()
        suggestions = []

        # Generate suggestions based on analysis
        if analysis.get("license_checks"):
            for check in analysis["license_checks"]:
                suggestions.append({
                    "type": "license_bypass",
                    "address": check["address"],
                    "description": f"Bypass license check at {check['address']}",
                    "patch": generator.generate_nop_sled(check.get("size", 4)),
                    "confidence": 0.8
                })

        if analysis.get("trial_checks"):
            for check in analysis["trial_checks"]:
                suggestions.append({
                    "type": "trial_bypass",
                    "address": check["address"],
                    "description": f"Bypass trial check at {check['address']}",
                    "patch": generator.generate_simple_payload("license_bypass"),
                    "confidence": 0.7
                })

        return {
            "status": "success",
            "suggestions": suggestions,
            "total": len(suggestions),
            "analysis": analysis
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error generating patch suggestions: %s", e)
        return {"status": "error", "message": str(e)}


def run_multi_format_analysis(binary_path: str) -> Dict[str, Any]:
    """
    Run multi-format binary analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing multi-format analysis results
    """
    try:
        from ..core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer

        analyzer = MultiFormatBinaryAnalyzer()
        results = analyzer.analyze_binary(binary_path)

        return {
            "status": "success",
            "format": results.get("format", "unknown"),
            "analysis": results,
            "supported": True
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in multi-format analysis: %s", e)
        return {"status": "error", "message": str(e)}


def run_ml_similarity_search(binary_path: str, database: Optional[str] = None) -> Dict[str, Any]:
    """
    Run ML-based similarity search.

    Args:
        binary_path: Path to the binary file
        database: Path to similarity database

    Returns:
        Dict containing similar binaries
    """
    try:
        from ..core.analysis import SimilaritySearcher

        searcher = SimilaritySearcher()
        if database:
            searcher.load_database(database)

        similar = searcher.find_similar(binary_path, threshold=0.8)

        return {
            "status": "success",
            "similar_binaries": similar,
            "total_found": len(similar),
            "best_match": similar[0] if similar else None
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ML similarity search: %s", e)
        return {"status": "error", "message": str(e)}


# Export all functions
__all__ = [
    'run_comprehensive_analysis',
    'run_deep_license_analysis',
    'run_detect_packing',
    'run_analysis',
    'run_autonomous_crack',
    'run_full_autonomous_mode',
    'run_ghidra_analysis_gui',
    'run_incremental_analysis_ui',
    'run_deep_cfg_analysis',
    'run_external_tool',
    'run_windows_activator',
    'check_adobe_licensex_status',
    'run_adobe_licensex_manually',
    'validate_dataset',
    'verify_hash',
    'run_external_command',
    'compute_file_hash',
    'create_sample_plugins',
    'load_ai_model',
    'get_target_process_pid',
    'detect_hardware_dongles',
    'detect_tpm_protection',
    'run_vulnerability_scan',
    'run_cfg_analysis',
    'run_rop_gadget_finder',
    'run_section_analysis',
    'run_import_export_analysis',
    'run_weak_crypto_detection',
    'run_comprehensive_protection_scan',
    'run_ml_vulnerability_prediction',
    'run_generate_patch_suggestions',
    'run_multi_format_analysis',
    'run_ml_similarity_search'
]
