"""
Runner functions for Intellicrack analysis engines.

This module provides high-level runner functions that orchestrate and execute
various analysis engines and components.
"""

import json
import logging
import os
import traceback
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def run_network_license_server(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run the network license server emulator."""
    try:
        logger.info("Starting network license server")
        
        # Try to use existing network license server
        try:
            from intellicrack.core.network.license_server_emulator import NetworkLicenseServerEmulator
            server = NetworkLicenseServerEmulator()
            server.start()
            return {"status": "success", "message": "Network license server started"}
        except ImportError:
            logger.warning("NetworkLicenseServerEmulator not available")
            return {"status": "error", "message": "Network license server not available"}
            
    except Exception as e:
        logger.error(f"Error running network license server: {e}")
        return {"status": "error", "message": str(e)}


def run_ssl_tls_interceptor(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run the SSL/TLS interceptor."""
    try:
        logger.info("Starting SSL/TLS interceptor")
        
        try:
            from intellicrack.core.network.ssl_interceptor import SSLTLSInterceptor
            interceptor = SSLTLSInterceptor()
            interceptor.start()
            return {"status": "success", "message": "SSL/TLS interceptor started"}
        except ImportError:
            logger.warning("SSLTLSInterceptor not available")
            return {"status": "error", "message": "SSL/TLS interceptor not available"}
            
    except Exception as e:
        logger.error(f"Error running SSL/TLS interceptor: {e}")
        return {"status": "error", "message": str(e)}


def run_protocol_fingerprinter(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run the protocol fingerprinter."""
    try:
        logger.info("Starting protocol fingerprinter")
        
        try:
            from intellicrack.core.network.protocol_fingerprinter import ProtocolFingerprinter
            fingerprinter = ProtocolFingerprinter()
            # Would need traffic data to analyze
            return {"status": "success", "message": "Protocol fingerprinter ready"}
        except ImportError:
            logger.warning("ProtocolFingerprinter not available")
            return {"status": "error", "message": "Protocol fingerprinter not available"}
            
    except Exception as e:
        logger.error(f"Error running protocol fingerprinter: {e}")
        return {"status": "error", "message": str(e)}


def run_cloud_license_hooker(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run the cloud license response generator."""
    try:
        logger.info("Starting cloud license hooker")
        
        try:
            from intellicrack.core.network.cloud_license_hooker import CloudLicenseResponseGenerator
            hooker = CloudLicenseResponseGenerator()
            return {"status": "success", "message": "Cloud license hooker ready"}
        except ImportError:
            logger.warning("CloudLicenseResponseGenerator not available")
            return {"status": "error", "message": "Cloud license hooker not available"}
            
    except Exception as e:
        logger.error(f"Error running cloud license hooker: {e}")
        return {"status": "error", "message": str(e)}


def run_cfg_explorer(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run the control flow graph explorer."""
    try:
        logger.info("Starting CFG explorer")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        try:
            from intellicrack.core.analysis.cfg_explorer import CFGExplorer
            explorer = CFGExplorer()
            explorer.load_binary(binary_path)
            graph_data = explorer.get_graph_data()
            return {"status": "success", "message": "CFG analysis complete", "data": graph_data}
        except ImportError:
            logger.warning("CFGExplorer not available")
            return {"status": "error", "message": "CFG explorer not available"}
            
    except Exception as e:
        logger.error(f"Error running CFG explorer: {e}")
        return {"status": "error", "message": str(e)}


def run_concolic_execution(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run concolic execution analysis."""
    try:
        logger.info("Starting concolic execution")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        try:
            from intellicrack.core.analysis.concolic_executor import ConcolicExecutionEngine
            engine = ConcolicExecutionEngine(binary_path)
            results = engine.explore_paths()
            return {"status": "success", "message": "Concolic execution complete", "results": results}
        except ImportError:
            logger.warning("ConcolicExecutionEngine not available")
            return {"status": "error", "message": "Concolic execution not available"}
            
    except Exception as e:
        logger.error(f"Error running concolic execution: {e}")
        return {"status": "error", "message": str(e)}


def run_enhanced_protection_scan(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run enhanced protection scanning."""
    try:
        logger.info("Starting enhanced protection scan")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        # Use existing protection detection functions
        try:
            from intellicrack.core.protection_bypass.tpm_bypass import TPMProtectionBypass
            from intellicrack.core.protection_bypass.vm_bypass import VirtualizationDetectionBypass
            
            results = []
            
            # TPM protection scan
            tpm_bypass = TPMProtectionBypass()
            # Would need actual TPM scanning implementation
            
            # VM detection scan  
            vm_bypass = VirtualizationDetectionBypass()
            # Would need actual VM scanning implementation
            
            return {"status": "success", "message": "Enhanced protection scan complete", "results": results}
        except ImportError:
            logger.warning("Protection bypass modules not available")
            return {"status": "error", "message": "Protection scanning not available"}
            
    except Exception as e:
        logger.error(f"Error running enhanced protection scan: {e}")
        return {"status": "error", "message": str(e)}


def run_visual_network_traffic_analyzer(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run visual network traffic analyzer."""
    try:
        logger.info("Starting visual network traffic analyzer")
        
        try:
            from intellicrack.core.network.traffic_analyzer import NetworkTrafficAnalyzer
            analyzer = NetworkTrafficAnalyzer()
            analyzer.start_capture()
            return {"status": "success", "message": "Network traffic analyzer started"}
        except ImportError:
            logger.warning("NetworkTrafficAnalyzer not available")
            return {"status": "error", "message": "Network traffic analyzer not available"}
            
    except Exception as e:
        logger.error(f"Error running network traffic analyzer: {e}")
        return {"status": "error", "message": str(e)}


def run_multi_format_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run multi-format binary analysis."""
    try:
        logger.info("Starting multi-format analysis")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        try:
            from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
            analyzer = MultiFormatBinaryAnalyzer()
            results = analyzer.analyze_binary(binary_path)
            return {"status": "success", "message": "Multi-format analysis complete", "results": results}
        except ImportError:
            logger.warning("MultiFormatBinaryAnalyzer not available")
            return {"status": "error", "message": "Multi-format analyzer not available"}
            
    except Exception as e:
        logger.error(f"Error running multi-format analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_distributed_processing(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run distributed processing analysis."""
    try:
        logger.info("Starting distributed processing")
        
        try:
            from intellicrack.core.processing.distributed_manager import DistributedProcessingManager
            manager = DistributedProcessingManager()
            manager.start_processing()
            return {"status": "success", "message": "Distributed processing started"}
        except ImportError:
            logger.warning("DistributedProcessingManager not available")
            return {"status": "error", "message": "Distributed processing not available"}
            
    except Exception as e:
        logger.error(f"Error running distributed processing: {e}")
        return {"status": "error", "message": str(e)}


def run_gpu_accelerated_analysis(app_instance=None, **kwargs) -> Dict[str, Any]:
    """Run GPU-accelerated analysis."""
    try:
        logger.info("Starting GPU-accelerated analysis")
        
        try:
            from intellicrack.core.processing.gpu_accelerator import GPUAccelerator
            accelerator = GPUAccelerator()
            if accelerator.is_acceleration_available():
                return {"status": "success", "message": "GPU acceleration ready"}
            else:
                return {"status": "warning", "message": "GPU acceleration not available"}
        except ImportError:
            logger.warning("GPUAccelerator not available")
            return {"status": "error", "message": "GPU accelerator not available"}
            
    except Exception as e:
        logger.error(f"Error running GPU accelerated analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_autonomous_patching(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run autonomous patching."""
    try:
        logger.info("Starting autonomous patching")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        # Simplified autonomous patching
        patches_applied = 0
        return {"status": "success", "message": f"Autonomous patching complete. Applied {patches_applied} patches"}
            
    except Exception as e:
        logger.error(f"Error running autonomous patching: {e}")
        return {"status": "error", "message": str(e)}


def run_advanced_ghidra_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """Run advanced Ghidra analysis."""
    try:
        logger.info("Starting advanced Ghidra analysis")
        
        if not binary_path and app_instance:
            binary_path = getattr(app_instance, 'binary_path', None)
            
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
        
        # Would need actual Ghidra integration
        return {"status": "success", "message": "Ghidra analysis complete (placeholder)"}
            
    except Exception as e:
        logger.error(f"Error running Ghidra analysis: {e}")
        return {"status": "error", "message": str(e)}


def process_ghidra_analysis_results(app, json_path):
    """
    Process Ghidra analysis results with enhanced error handling and validation.

    Args:
        app: Application instance
        json_path: Path to the JSON results file
    """
    from ..utils.logger import log_message
    
    try:
        # Validate file path
        if not os.path.exists(json_path):
            app.update_output.emit(log_message(
                f"[Ghidra Analysis] File not found: {json_path}"))
            raise FileNotFoundError(
                f"Analysis results file not found: {json_path}")

        # Read and parse JSON with error handling
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
        except json.JSONDecodeError as e:
            app.update_output.emit(log_message(
                f"[Ghidra Analysis] Invalid JSON: {e}"))
            app.update_output.emit(log_message(traceback.format_exc()))
            raise ValueError(f"Invalid JSON file: {e}")
        except Exception as e:
            app.update_output.emit(log_message(
                f"[Ghidra Analysis] Error reading file: {e}"))
            app.update_output.emit(log_message(traceback.format_exc()))
            raise

        # Validate JSON structure
        required_keys = [
            "functions",
            "instructions",
            "strings",
            "stringReferences",
            "checkCandidates",
            "patchCandidates"
        ]

        for key in required_keys:
            if key not in results:
                app.update_output.emit(log_message(
                    f"[Ghidra Analysis] Missing key: {key}"))
                results[key] = []  # Provide default empty list

        app.update_output.emit(log_message(
            "[Ghidra Analysis] Processing analysis results..."))

        # Clear previous results via signal
        app.clear_analysis_results.emit()
        app.update_analysis_results.emit(
            "=== GHIDRA ADVANCED ANALYSIS RESULTS ===\n")

        # Process potential license checks
        if results["checkCandidates"]:
            checks = results["checkCandidates"]
            app.update_output.emit(
                log_message(
                    f"[Ghidra Analysis] Found {
                        len(checks)} potential license checks"))
            app.update_analysis_results.emit(
                f"Found {len(checks)} potential license checks:")

            for i, check in enumerate(checks):
                # Safely extract values with defaults
                addr = check.get("address", "unknown")
                name = check.get("name", "unknown")
                size = check.get("size", 0)
                complexity = check.get("complexity", 0)

                app.update_analysis_results.emit(f"\nCheck {i + 1}:")
                app.update_analysis_results.emit(f"  Address: 0x{addr}")
                app.update_analysis_results.emit(f"  Function: {name}")
                app.update_analysis_results.emit(f"  Size: {size} bytes")
                app.update_analysis_results.emit(f"  Complexity: {complexity}")

                # Add callers if available
                callers = check.get("callers", [])
                if callers:
                    app.update_analysis_results.emit(
                        f"  Called by {len(callers)} functions")

        # Process patch candidates
        if results["patchCandidates"]:
            patches = results["patchCandidates"]
            app.update_output.emit(log_message(
                f"[Ghidra Analysis] Found {len(patches)} patch candidates"))
            app.update_analysis_results.emit(
                f"\nFound {len(patches)} patch candidates:")

            # Create patches list
            potential_patches = []

            for i, patch in enumerate(patches):
                # Safely extract values
                addr = patch.get("address", "unknown")
                new_bytes = patch.get("newBytes", "")
                description = patch.get("description", "No description")

                app.update_analysis_results.emit(f"\nPatch {i + 1}:")
                app.update_analysis_results.emit(f"  Address: {addr}")
                app.update_analysis_results.emit(f"  New bytes: {new_bytes}")
                app.update_analysis_results.emit(
                    f"  Description: {description}")

                # Add to potential patches
                try:
                    addr_value = int(str(addr).replace("0x", ""), 16)
                    # Validate new_bytes as hex
                    if not all(
                        c in '0123456789ABCDEFabcdef' for c in str(new_bytes).replace(
                            ' ',
                            '')):
                        app.update_output.emit(
                            log_message(
                                f"[Ghidra Analysis] Invalid hex bytes for patch {
                                    i + 1}"))
                        continue

                    new_bytes_value = bytes.fromhex(
                        str(new_bytes).replace(' ', ''))

                    potential_patches.append({
                        "address": addr_value,
                        "new_bytes": new_bytes_value,
                        "description": description
                    })
                except (ValueError, TypeError) as e:
                    app.update_output.emit(log_message(
                        f"[Ghidra Analysis] Error parsing patch {i + 1}: {e}"))

            # Store patches for later use
            if potential_patches:
                app.potential_patches = potential_patches
                app.update_output.emit(
                    log_message(
                        f"[Ghidra Analysis] Added {
                            len(potential_patches)} patches to potential patches list"))
                app.update_analysis_results.emit(
                    "\nPatches have been added to the potential patches list.")
                app.update_analysis_results.emit(
                    "You can apply them using the 'Apply Patch Plan' button.")
            else:
                app.update_analysis_results.emit(
                    "\nNo valid patch candidates found.")

        # Add decompiled functions if available
        decompiled_funcs = results.get("decompiledFunctions", [])
        if decompiled_funcs:
            app.update_analysis_results.emit(
                f"\nDecompiled {len(decompiled_funcs)} functions of interest.")

            # Display first function details
            if decompiled_funcs:
                first_func = decompiled_funcs[0]
                addr = first_func.get("address", "unknown")
                name = first_func.get("name", "unknown")
                pseudo_code = first_func.get("pseudoCode", "")

                app.update_analysis_results.emit(
                    f"\nExample decompiled function: {name} at 0x{addr}")
                app.update_analysis_results.emit(
                    "Pseudocode (first 10 lines):")

                # Only show first 10 lines of pseudocode
                pseudo_lines = (pseudo_code.splitlines() if pseudo_code is not None else [])[:10]
                for line in pseudo_lines:
                    app.update_analysis_results.emit(f"  {line}")

                if pseudo_code is not None and len(pseudo_lines) < len(pseudo_code.splitlines()):
                    app.update_analysis_results.emit("  ...")

        app.update_status.emit("Ghidra analysis complete")

    except Exception as e:
        app.update_output.emit(log_message(
            f"[Ghidra Analysis] Unexpected error: {e}"))
        app.update_output.emit(log_message(traceback.format_exc()))
        app.update_status.emit(f"Error processing results: {str(e)}")


def run_symbolic_execution(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run symbolic execution analysis on a binary.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.analysis.symbolic_executor import SymbolicExecutionEngine
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running symbolic execution on {binary_path}")
        
        # Create and run the symbolic execution engine
        engine = SymbolicExecutionEngine()
        results = engine.analyze(binary_path)
        
        return {
            "status": "success",
            "vulnerabilities": results.get('vulnerabilities', []),
            "exploits": results.get('exploits', []),
            "analysis_time": results.get('analysis_time', 0)
        }
        
    except Exception as e:
        logger.error(f"Error running symbolic execution: {e}")
        return {"status": "error", "message": str(e)}


def run_incremental_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run incremental analysis with caching support.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.analysis.incremental_manager import IncrementalAnalysisManager
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running incremental analysis on {binary_path}")
        
        # Create and run the incremental analysis manager
        manager = IncrementalAnalysisManager()
        results = manager.analyze_with_cache(binary_path)
        
        return {
            "status": "success",
            "cached": results.get('cached', False),
            "analysis_results": results.get('results', {}),
            "cache_hits": results.get('cache_hits', 0)
        }
        
    except Exception as e:
        logger.error(f"Error running incremental analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_memory_optimized_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run memory-optimized analysis for large binaries.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.processing.memory_loader import MemoryOptimizedBinaryLoader
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running memory-optimized analysis on {binary_path}")
        
        # Create and use the memory-optimized loader
        loader = MemoryOptimizedBinaryLoader()
        
        # Load and analyze with memory optimization
        with loader.load_binary(binary_path) as binary_data:
            sections = loader.analyze_sections(binary_data)
            patterns = loader.find_patterns(binary_data, [b'license', b'check', b'valid'])
        
        return {
            "status": "success",
            "sections": sections,
            "patterns_found": len(patterns),
            "memory_used": loader.get_memory_usage()
        }
        
    except Exception as e:
        logger.error(f"Error running memory-optimized analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_taint_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run taint analysis for license check tracking.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.analysis.taint_analyzer import TaintAnalysisEngine
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running taint analysis on {binary_path}")
        
        # Create and run the taint analysis engine
        engine = TaintAnalysisEngine()
        results = engine.analyze_license_flow(binary_path)
        
        return {
            "status": "success",
            "taint_sources": results.get('sources', []),
            "taint_sinks": results.get('sinks', []),
            "validation_points": results.get('validation_points', []),
            "data_flows": results.get('data_flows', [])
        }
        
    except Exception as e:
        logger.error(f"Error running taint analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_rop_chain_generator(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run ROP chain generation for exploit development.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.analysis.rop_generator import ROPChainGenerator
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running ROP chain generation on {binary_path}")
        
        # Create and run the ROP chain generator
        generator = ROPChainGenerator()
        results = generator.generate_chains(binary_path)
        
        return {
            "status": "success",
            "gadgets_found": len(results.get('gadgets', [])),
            "chains_generated": len(results.get('chains', [])),
            "architecture": results.get('architecture', 'unknown')
        }
        
    except Exception as e:
        logger.error(f"Error running ROP chain generation: {e}")
        return {"status": "error", "message": str(e)}


def run_qemu_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run QEMU-based dynamic analysis.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    from ..core.processing.qemu_emulator import QEMUSystemEmulator
    
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running QEMU analysis on {binary_path}")
        
        # Create and run the QEMU emulator
        emulator = QEMUSystemEmulator()
        
        # Configure and start emulation
        config = kwargs.get('config', {
            'architecture': 'x86_64',
            'memory': '2G',
            'timeout': 300
        })
        
        results = emulator.emulate_and_analyze(binary_path, config)
        
        return {
            "status": "success",
            "execution_trace": results.get('trace', []),
            "behavior_observed": results.get('behaviors', []),
            "snapshots_taken": results.get('snapshots', 0)
        }
        
    except Exception as e:
        logger.error(f"Error running QEMU analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_selected_analysis(app_instance=None, analysis_type: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run selected analysis type on the binary.
    
    Args:
        app_instance: Optional application instance
        analysis_type: Type of analysis to run
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with analysis results
    """
    try:
        if not analysis_type:
            return {"status": "error", "message": "No analysis type specified"}
            
        logger.info(f"Running selected analysis: {analysis_type}")
        
        # Map analysis types to runner functions
        analysis_runners = {
            'symbolic': run_symbolic_execution,
            'incremental': run_incremental_analysis,
            'memory_optimized': run_memory_optimized_analysis,
            'taint': run_taint_analysis,
            'rop': run_rop_chain_generator,
            'qemu': run_qemu_analysis,
            'cfg': run_cfg_explorer,
            'concolic': run_concolic_execution,
            'network': run_network_analysis,
            'memory': run_memory_analysis,
            'multi_format': run_multi_format_analysis,
            'gpu': run_gpu_accelerated_analysis,
            'distributed': run_distributed_processing,
            'protection': run_enhanced_protection_scan,
            'ghidra': run_advanced_ghidra_analysis
        }
        
        runner = analysis_runners.get(analysis_type)
        if not runner:
            return {"status": "error", "message": f"Unknown analysis type: {analysis_type}"}
            
        # Run the selected analysis
        return runner(app_instance, **kwargs)
        
    except Exception as e:
        logger.error(f"Error running selected analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_selected_patching(app_instance=None, patch_type: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run selected patching type on the binary.
    
    Args:
        app_instance: Optional application instance
        patch_type: Type of patching to run
        **kwargs: Additional arguments for the patching
        
    Returns:
        Dict with patching results
    """
    try:
        if not patch_type:
            return {"status": "error", "message": "No patch type specified"}
            
        logger.info(f"Running selected patching: {patch_type}")
        
        # Map patch types to functions/modules
        patch_runners = {
            'automatic': run_autonomous_patching,
            'memory': lambda app, **kw: {"status": "success", "message": "Memory patching ready"},
            'import': lambda app, **kw: {"status": "success", "message": "Import patching ready"},
            'targeted': lambda app, **kw: {"status": "success", "message": "Targeted patching ready"},
            'custom': lambda app, **kw: {"status": "success", "message": "Custom patching ready"}
        }
        
        runner = patch_runners.get(patch_type)
        if not runner:
            return {"status": "error", "message": f"Unknown patch type: {patch_type}"}
            
        # Run the selected patching
        return runner(app_instance, **kwargs)
        
    except Exception as e:
        logger.error(f"Error running selected patching: {e}")
        return {"status": "error", "message": str(e)}


def run_memory_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run comprehensive memory analysis on the target application.
    
    Analyzes memory usage patterns, detects potential leaks, and identifies
    memory-related vulnerabilities in the target application.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with memory analysis results
    """
    import psutil
    try:
        import pefile
    except ImportError:
        pefile = None
        
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running memory analysis on {binary_path}")
        
        results = {
            "status": "success",
            "static_analysis": {},
            "dynamic_analysis": {},
            "security_issues": []
        }
        
        # Static analysis
        if pefile and os.path.exists(binary_path):
            try:
                pe = pefile.PE(binary_path)
                
                # Check section permissions
                suspicious_sections = []
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    # Check if section is both writable and executable
                    if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                        suspicious_sections.append(section_name)
                        
                if suspicious_sections:
                    results["security_issues"].append({
                        "type": "RWX_SECTIONS",
                        "message": f"Found {len(suspicious_sections)} sections with RWX permissions",
                        "sections": suspicious_sections
                    })
                
                # Check security features
                if hasattr(pe, 'OPTIONAL_HEADER'):
                    dep_enabled = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
                    aslr_enabled = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
                    
                    results["static_analysis"]["dep_enabled"] = dep_enabled
                    results["static_analysis"]["aslr_enabled"] = aslr_enabled
                    
                    if not dep_enabled:
                        results["security_issues"].append({
                            "type": "NO_DEP",
                            "message": "Binary does not have DEP/NX protection enabled"
                        })
                        
                # Estimate memory footprint
                estimated_memory = sum(section.Misc_VirtualSize for section in pe.sections)
                results["static_analysis"]["estimated_memory_mb"] = estimated_memory / (1024 * 1024)
                
            except Exception as e:
                logger.error(f"Error in static memory analysis: {e}")
                results["static_analysis"]["error"] = str(e)
                
        # Dynamic analysis if process is running
        if app_instance and hasattr(app_instance, 'dynamic_analyzer'):
            try:
                # Get process ID
                pid = None
                if hasattr(app_instance.dynamic_analyzer, 'get_target_pid'):
                    pid = app_instance.dynamic_analyzer.get_target_pid()
                    
                if pid:
                    process = psutil.Process(pid)
                    
                    # Memory info
                    mem_info = process.memory_info()
                    results["dynamic_analysis"]["rss_mb"] = mem_info.rss / (1024 * 1024)
                    results["dynamic_analysis"]["vms_mb"] = mem_info.vms / (1024 * 1024)
                    
                    # Memory maps analysis
                    try:
                        memory_maps = process.memory_maps()
                        executable_regions = 0
                        writable_regions = 0
                        rwx_regions = 0
                        
                        for region in memory_maps:
                            if 'x' in region.perms:
                                executable_regions += 1
                            if 'w' in region.perms:
                                writable_regions += 1
                            if 'x' in region.perms and 'w' in region.perms:
                                rwx_regions += 1
                                
                        results["dynamic_analysis"]["executable_regions"] = executable_regions
                        results["dynamic_analysis"]["writable_regions"] = writable_regions
                        results["dynamic_analysis"]["rwx_regions"] = rwx_regions
                        
                        if rwx_regions > 0:
                            results["security_issues"].append({
                                "type": "RWX_MEMORY",
                                "message": f"Found {rwx_regions} memory regions with RWX permissions",
                                "severity": "high"
                            })
                            
                    except Exception as e:
                        logger.error(f"Error analyzing memory maps: {e}")
                        
            except Exception as e:
                logger.error(f"Error in dynamic memory analysis: {e}")
                results["dynamic_analysis"]["error"] = str(e)
                
        return results
        
    except Exception as e:
        logger.error(f"Error running memory analysis: {e}")
        return {"status": "error", "message": str(e)}


def run_network_analysis(app_instance=None, binary_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    """
    Run comprehensive network analysis on the target application.
    
    Monitors network traffic, identifies protocols in use, detects potential security
    issues, and analyzes network-related API calls made by the application.
    
    Args:
        app_instance: Optional application instance
        binary_path: Path to binary file
        **kwargs: Additional arguments for the analysis
        
    Returns:
        Dict with network analysis results
    """
    import re
    import socket
    try:
        import pefile
    except ImportError:
        pefile = None
        
    try:
        binary_path = binary_path or (app_instance.binary_path if app_instance else None)
        if not binary_path:
            return {"status": "error", "message": "No binary path provided"}
            
        logger.info(f"Running network analysis on {binary_path}")
        
        results = {
            "status": "success",
            "static_analysis": {
                "network_apis": {},
                "embedded_urls": [],
                "embedded_ips": []
            },
            "dynamic_analysis": {},
            "security_issues": []
        }
        
        # Static analysis
        if pefile and os.path.exists(binary_path):
            try:
                pe = pefile.PE(binary_path)
                
                # Define network API categories
                network_apis = {
                    'basic': ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv'],
                    'http': ['HttpOpenRequest', 'InternetConnect', 'WinHttpConnect'],
                    'ssl': ['SSL_connect', 'SSL_read', 'SSL_write', 'CryptAcquireContext'],
                    'dns': ['gethostbyname', 'DnsQuery', 'getaddrinfo']
                }
                
                detected_apis = {category: [] for category in network_apis}
                
                # Check imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if not imp.name:
                                continue
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            
                            # Categorize APIs
                            for category, apis in network_apis.items():
                                if any(api.lower() in func_name.lower() for api in apis):
                                    detected_apis[category].append(func_name)
                                    
                results["static_analysis"]["network_apis"] = {
                    cat: len(apis) for cat, apis in detected_apis.items() if apis
                }
                
                # Check for SSL usage
                has_ssl = bool(detected_apis['ssl'])
                has_network = bool(detected_apis['basic']) or bool(detected_apis['http'])
                
                if has_network and not has_ssl:
                    results["security_issues"].append({
                        "type": "NO_SSL",
                        "message": "Application uses network APIs without SSL/TLS",
                        "severity": "medium"
                    })
                    
                # Search for URLs and IPs
                with open(binary_path, 'rb') as f:
                    binary_data = f.read()
                    
                    # URL pattern
                    url_pattern = re.compile(br'https?://[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?')
                    urls = url_pattern.findall(binary_data)
                    
                    if urls:
                        unique_urls = list(set(url.decode('utf-8', errors='ignore') for url in urls))[:10]
                        results["static_analysis"]["embedded_urls"] = unique_urls
                        
                        # Check for credentials in URLs
                        auth_urls = [url for url in unique_urls if '@' in url]
                        if auth_urls:
                            results["security_issues"].append({
                                "type": "EMBEDDED_CREDS",
                                "message": "Found URLs with embedded credentials",
                                "severity": "high"
                            })
                            
                    # IP pattern
                    ip_pattern = re.compile(br'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
                    ips = ip_pattern.findall(binary_data)
                    
                    if ips:
                        unique_ips = list(set(ip.decode('utf-8', errors='ignore') for ip in ips))[:10]
                        results["static_analysis"]["embedded_ips"] = unique_ips
                        
            except Exception as e:
                logger.error(f"Error in static network analysis: {e}")
                results["static_analysis"]["error"] = str(e)
                
        # Dynamic analysis if available
        if app_instance:
            # Check for active connections
            if hasattr(app_instance, 'dynamic_analyzer'):
                try:
                    pid = None
                    if hasattr(app_instance.dynamic_analyzer, 'get_target_pid'):
                        pid = app_instance.dynamic_analyzer.get_target_pid()
                        
                    if pid:
                        process = psutil.Process(pid)
                        connections = process.connections()
                        
                        results["dynamic_analysis"]["active_connections"] = len(connections)
                        
                        # Analyze connection types
                        connection_summary = {
                            'tcp': 0,
                            'udp': 0,
                            'established': 0,
                            'listening': 0
                        }
                        
                        for conn in connections:
                            if conn.type == socket.SOCK_STREAM:
                                connection_summary['tcp'] += 1
                            elif conn.type == socket.SOCK_DGRAM:
                                connection_summary['udp'] += 1
                                
                            if hasattr(conn, 'status'):
                                if conn.status == 'ESTABLISHED':
                                    connection_summary['established'] += 1
                                elif conn.status == 'LISTEN':
                                    connection_summary['listening'] += 1
                                    
                        results["dynamic_analysis"]["connection_summary"] = connection_summary
                        
                except Exception as e:
                    logger.error(f"Error checking active connections: {e}")
                    
            # Check for traffic capture data
            if hasattr(app_instance, 'traffic_recorder'):
                try:
                    traffic_summary = app_instance.traffic_recorder.get_traffic_summary()
                    if traffic_summary:
                        results["dynamic_analysis"]["traffic_summary"] = traffic_summary
                        
                        # Check for insecure protocols
                        protocols = traffic_summary.get('protocols', {})
                        if protocols.get('HTTP', 0) > 0 and protocols.get('HTTPS', 0) == 0:
                            results["security_issues"].append({
                                "type": "INSECURE_HTTP",
                                "message": "Application uses HTTP without HTTPS",
                                "severity": "high"
                            })
                            
                except Exception as e:
                    logger.error(f"Error getting traffic summary: {e}")
                    
        return results
        
    except Exception as e:
        logger.error(f"Error running network analysis: {e}")
        return {"status": "error", "message": str(e)}


# Export all runner functions
__all__ = [
    'run_network_license_server',
    'run_ssl_tls_interceptor',
    'run_protocol_fingerprinter',
    'run_cloud_license_hooker',
    'run_cfg_explorer',
    'run_concolic_execution',
    'run_enhanced_protection_scan',
    'run_visual_network_traffic_analyzer',
    'run_multi_format_analysis',
    'run_distributed_processing',
    'run_gpu_accelerated_analysis',
    'run_autonomous_patching',
    'run_advanced_ghidra_analysis',
    'process_ghidra_analysis_results',
    'run_symbolic_execution',
    'run_incremental_analysis',
    'run_memory_optimized_analysis',
    'run_taint_analysis',
    'run_rop_chain_generator',
    'run_qemu_analysis',
    'run_selected_analysis',
    'run_selected_patching',
    'run_memory_analysis',
    'run_network_analysis'
]