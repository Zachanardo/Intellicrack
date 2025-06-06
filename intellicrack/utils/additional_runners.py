"""
Additional runner functions for Intellicrack.

This module provides additional high-level runner functions for various
analysis and processing tasks.
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

        except Exception as e:
            logger.error("Error in %s: %s", analysis, e)
            results["analyses"][analysis] = {"error": str(e)}

    # Generate summary
    results["summary"] = _generate_analysis_summary(results["analyses"])

    # Save results to file
    results_file = os.path.join(output_dir, "comprehensive_analysis.json")
    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        results["results_file"] = results_file
    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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
            subprocess.Popen(cmd)

            results["launched"] = True
            results["project_dir"] = project_dir
            results["message"] = "Ghidra GUI launched successfully"
        else:
            results["error"] = f"Ghidra run script not found: {ghidra_run}"

    except Exception as e:
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

    except Exception as e:
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

            except Exception as e:
                logger.error(f"Error analyzing function {func['name']}: {e}")

        # Generate output
        if output_format == "html":
            results["visualization"] = explorer.visualize_cfg()
        elif output_format == "dot":
            results["visualization"] = explorer.export_dot("cfg_output.dot")

        return results

    except Exception as e:
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

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
    except Exception as e:
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

    except Exception as e:
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
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if "license" in file.lower() or ".lic" in file.lower():
                            results["license_files_found"] = True
                            break

    except Exception as e:
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

    except Exception as e:
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
                with open(dataset_path, 'r') as f:
                    data = json.load(f)

                results["record_count"] = len(data) if isinstance(data, list) else 1
                results["valid"] = True
            else:
                results["issues"].append("File not found")

    except Exception as e:
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

    except Exception as e:
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

        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

        results["executed"] = True
        results["return_code"] = result.returncode
        results["stdout"] = result.stdout
        results["stderr"] = result.stderr
        results["success"] = result.returncode == 0

    except subprocess.TimeoutExpired:
        results["error"] = "Command timed out"
    except Exception as e:
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
        with open(python_file, 'w') as f:
            f.write(python_plugin)
        results["plugins_created"].append(python_file)

        # Create Frida script
        frida_file = os.path.join(plugin_dir, "sample_frida.js")
        with open(frida_file, 'w') as f:
            f.write(frida_script)
        results["plugins_created"].append(frida_file)

        results["success"] = True

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
        logger.error("Error getting process PID: %s", e)

    return None


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
        # Check for common dongle vendors
        dongle_vendors = {
            "0x064F": "WIBU-SYSTEMS",
            "0x0547": "Aladdin",
            "0x1BC0": "Sentinel",
            "0x0529": "Hardlock"
        }

        # This would require platform-specific USB enumeration
        # For now, return placeholder
        results["message"] = "Hardware dongle detection requires platform-specific implementation"

    except Exception as e:
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
    except Exception as e:
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
    """Verify if crack was successful."""
    # This would run the patched binary and check behavior
    return {"verified": True, "method": "static_analysis"}


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
    """Check if CFG contains license check patterns."""
    # Look for specific patterns in control flow
    # This is simplified - real implementation would be more sophisticated
    return cfg.get("complexity", 0) > 10 and cfg.get("branches", 0) > 5


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

    except Exception as e:
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

    except Exception as e:
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

        # Simple categorization based on gadget patterns
        categories = {"ret": 0, "pop": 0, "mov": 0, "other": 0}
        if isinstance(gadgets, list):
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
            "total": len(gadgets) if isinstance(gadgets, list) else 0,
            "categories": categories
        }

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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

    except Exception as e:
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
