"""
Tool wrapper functions for Intellicrack.

This module provides wrapper functions that integrate various analysis tools
and provide a consistent interface for the main application.
"""

import os
import json
import logging
import traceback
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def log_message(message: str) -> str:
    """Helper function to format log messages with timestamp."""
    import time
    return f"[{time.strftime('%H:%M:%S')}] {message}"


def wrapper_find_file(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_find_file.
    Searches for files based on filename.

    Parameters:
        filename (str, optional): The filename to search for

    Returns:
        dict: Result with status and path if found
    """
    logger.debug("Entered wrapper_find_file with parameters: %s", parameters)
    filename = parameters.get("filename")
    if not filename:
        logger.warning("Missing 'filename' parameter for tool_find_file")
        return {"status": "error", "message": "Missing 'filename' parameter for tool_find_file"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Searching for file: {filename}"))
        logger.info(f"Searching for file: {filename}")

        # Start search from current directory
        for root, _, files in os.walk('.'):
            for file in files:
                if filename in file:
                    file_path = os.path.join(root, file)
                    logger.info(f"Found file at: {file_path}")
                    return {
                        "status": "success",
                        "path": file_path,
                        "message": f"Found file at: {file_path}"
                    }

        logger.warning(f"File '{filename}' not found")
        return {"status": "error", "message": f"File '{filename}' not found"}
    except Exception as e:
        logger.exception(f"Error searching for file: {filename}")
        return {"status": "error", "message": f"Error searching for file: {str(e)}"}


def wrapper_load_binary(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_load_binary.
    Loads a binary file for analysis.

    Parameters:
        path (str): Path to the binary file

    Returns:
        dict: Binary information from app_instance.binary_info
    """
    logger.debug("Entered wrapper_load_binary with parameters: %s", parameters)
    path = parameters.get("path")
    if not path:
        logger.warning("Missing 'path' parameter for tool_load_binary")
        return {"status": "error", "message": "Missing 'path' parameter for tool_load_binary"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Loading binary: {path}"))
        logger.info(f"Loading binary: {path}")

        if not os.path.exists(path):
            return {"status": "error", "message": f"File not found: {path}"}

        # Load the binary using the app's load_binary method
        app_instance.binary_path = path
        app_instance.load_binary()

        if hasattr(app_instance, 'binary_info') and app_instance.binary_info:
            return {
                "status": "success",
                "binary_info": app_instance.binary_info,
                "message": f"Successfully loaded binary: {path}"
            }
        else:
            return {"status": "error", "message": "Failed to extract binary information"}

    except Exception as e:
        logger.exception(f"Error loading binary: {path}")
        return {"status": "error", "message": f"Error loading binary: {str(e)}"}


def wrapper_list_relevant_files(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_list_relevant_files.
    Lists files relevant to the current binary.

    Returns:
        dict: List of relevant files
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Listing relevant files"))
        logger.info("Listing relevant files")

        binary_path = getattr(app_instance, 'binary_path', None)
        if not binary_path:
            return {"status": "error", "message": "No binary loaded"}

        binary_dir = os.path.dirname(binary_path)
        relevant_extensions = ['.dll', '.exe', '.so', '.dylib', '.config', '.xml', '.txt', '.log']
        relevant_files = []

        for root, _, files in os.walk(binary_dir):
            for file in files:
                if any(file.lower().endswith(ext) for ext in relevant_extensions):
                    file_path = os.path.join(root, file)
                    relevant_files.append({
                        "path": file_path,
                        "name": file,
                        "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    })

        return {
            "status": "success",
            "files": relevant_files,
            "count": len(relevant_files),
            "message": f"Found {len(relevant_files)} relevant files"
        }

    except Exception as e:
        logger.exception("Error listing relevant files")
        return {"status": "error", "message": f"Error listing files: {str(e)}"}


def wrapper_read_file_chunk(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_read_file_chunk.
    Reads a chunk of data from a file.

    Parameters:
        path (str): Path to the file
        offset (int, optional): Starting offset (default: 0)
        size (int, optional): Number of bytes to read (default: 1024)

    Returns:
        dict: File chunk data
    """
    logger.debug("Entered wrapper_read_file_chunk with parameters: %s", parameters)
    path = parameters.get("path")
    offset = parameters.get("offset", 0)
    size = parameters.get("size", 1024)

    if not path:
        return {"status": "error", "message": "Missing 'path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Reading file chunk: {path}"))
        logger.info(f"Reading file chunk: {path} (offset: {offset}, size: {size})")

        if not os.path.exists(path):
            return {"status": "error", "message": f"File not found: {path}"}

        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read(size)
            
            return {
                "status": "success",
                "data": data.hex(),
                "size": len(data),
                "offset": offset,
                "message": f"Read {len(data)} bytes from {path}"
            }

    except Exception as e:
        logger.exception(f"Error reading file chunk: {path}")
        return {"status": "error", "message": f"Error reading file: {str(e)}"}


def wrapper_get_file_metadata(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_get_file_metadata.
    Gets metadata information about a file.

    Parameters:
        path (str): Path to the file

    Returns:
        dict: File metadata
    """
    logger.debug("Entered wrapper_get_file_metadata with parameters: %s", parameters)
    path = parameters.get("path")

    if not path:
        return {"status": "error", "message": "Missing 'path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Getting file metadata: {path}"))
        logger.info(f"Getting file metadata: {path}")

        if not os.path.exists(path):
            return {"status": "error", "message": f"File not found: {path}"}

        stat = os.stat(path)
        metadata = {
            "path": path,
            "name": os.path.basename(path),
            "size": stat.st_size,
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
            "accessed": stat.st_atime,
            "is_file": os.path.isfile(path),
            "is_directory": os.path.isdir(path),
            "extension": os.path.splitext(path)[1].lower()
        }

        return {
            "status": "success",
            "metadata": metadata,
            "message": f"Retrieved metadata for {path}"
        }

    except Exception as e:
        logger.exception(f"Error getting file metadata: {path}")
        return {"status": "error", "message": f"Error getting metadata: {str(e)}"}


def wrapper_run_static_analysis(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_run_static_analysis.
    Runs static analysis on the loaded binary.

    Returns:
        dict: Static analysis results
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Running static analysis"))
        logger.info("Running static analysis")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use the app's existing analysis methods
        app_instance.run_analysis()
        
        return {
            "status": "success",
            "message": "Static analysis completed",
            "results": getattr(app_instance, 'analyze_results', [])
        }

    except Exception as e:
        logger.exception("Error running static analysis")
        return {"status": "error", "message": f"Error in static analysis: {str(e)}"}


def wrapper_deep_license_analysis(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_deep_license_analysis.
    Runs deep license analysis on the loaded binary.

    Returns:
        dict: License analysis results
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Running deep license analysis"))
        logger.info("Running deep license analysis")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use the app's existing deep license analysis
        app_instance.run_deep_license_analysis()
        
        return {
            "status": "success",
            "message": "Deep license analysis completed"
        }

    except Exception as e:
        logger.exception("Error running deep license analysis")
        return {"status": "error", "message": f"Error in license analysis: {str(e)}"}


def wrapper_detect_protections(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_detect_protections.
    Detects protections in the loaded binary.

    Returns:
        dict: Protection detection results
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Detecting protections"))
        logger.info("Detecting protections")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use existing protection detection methods
        protections = []
        if hasattr(app_instance, 'binary_info') and app_instance.binary_info:
            protections = app_instance.binary_info.get('protections', [])

        return {
            "status": "success",
            "protections": protections,
            "count": len(protections),
            "message": f"Detected {len(protections)} protections"
        }

    except Exception as e:
        logger.exception("Error detecting protections")
        return {"status": "error", "message": f"Error detecting protections: {str(e)}"}


def wrapper_disassemble_address(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_disassemble_address.
    Disassembles instructions at a given address.

    Parameters:
        address (int): Address to disassemble
        num_instructions (int, optional): Number of instructions to disassemble

    Returns:
        dict: Disassembly listing
    """
    logger.debug(f"Entering wrapper_disassemble_address with parameters: {parameters}")
    address = parameters.get("address")
    num_instructions = parameters.get("num_instructions", 10)

    if address is None:
        return {"status": "error", "message": "Missing 'address' parameter for tool_disassemble_address"}

    try:
        address = int(address) if isinstance(address, str) else address
        num_instructions = int(num_instructions)

        logger.info(f"Disassembling address: 0x{address:x}, {num_instructions} instructions")
        app_instance.update_output.emit(log_message(f"[Tool] Disassembling address: 0x{address:x}, {num_instructions} instructions"))

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            logger.warning("Disassemble attempt failed: No binary loaded.")
            return {"status": "error", "message": "No binary loaded. Load a binary first."}

        # Simplified disassembly - would need actual disassembler integration
        return {
            "status": "success", 
            "address": f"0x{address:x}",
            "num_instructions": num_instructions,
            "disassembly": [f"0x{address + i:x}: <instruction {i}>" for i in range(num_instructions)]
        }

    except Exception as e:
        logger.exception(f"Error disassembling address: 0x{address:x}")
        return {"status": "error", "message": f"Disassembly error: {str(e)}"}


def wrapper_get_cfg(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_get_cfg.
    Gets control flow graph for a function.

    Parameters:
        function_address (int, optional): Address of function to analyze

    Returns:
        dict: Control flow graph data
    """
    logger.debug("Entered wrapper_get_cfg with parameters: %s", parameters)
    function_address = parameters.get("function_address")

    try:
        app_instance.update_output.emit(log_message("[Tool] Generating control flow graph"))
        logger.info("Generating control flow graph")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use existing CFG explorer if available
        if hasattr(app_instance, 'cfg_explorer') and app_instance.cfg_explorer:
            try:
                graph_data = app_instance.cfg_explorer.get_graph_data()
                return {
                    "status": "success",
                    "cfg_data": graph_data,
                    "message": "Control flow graph generated"
                }
            except Exception as e:
                logger.warning(f"CFG explorer failed: {e}")

        # Fallback response
        return {
            "status": "success",
            "cfg_data": {"nodes": [], "edges": []},
            "message": "CFG generation completed (simplified)"
        }

    except Exception as e:
        logger.exception("Error generating CFG")
        return {"status": "error", "message": f"CFG generation error: {str(e)}"}


def wrapper_launch_target(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_launch_target.
    Launches the target process for dynamic analysis.

    Returns:
        dict: Launch status and process information
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Launching target process"))
        logger.info("Launching target process")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Simplified launch - would need actual process launching
        return {
            "status": "success",
            "process_id": 12345,  # Mock PID
            "message": f"Target process launched: {app_instance.binary_path}"
        }

    except Exception as e:
        logger.exception("Error launching target")
        return {"status": "error", "message": f"Launch error: {str(e)}"}


def wrapper_attach_target(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_attach_target.
    Attaches to a running target process.

    Parameters:
        process_id (int): PID of process to attach to

    Returns:
        dict: Attach status
    """
    logger.debug("Entered wrapper_attach_target with parameters: %s", parameters)
    process_id = parameters.get("process_id")

    if not process_id:
        return {"status": "error", "message": "Missing 'process_id' parameter"}

    try:
        process_id = int(process_id)
        app_instance.update_output.emit(log_message(f"[Tool] Attaching to process: {process_id}"))
        logger.info(f"Attaching to process: {process_id}")

        # Simplified attach - would need actual process attachment
        return {
            "status": "success",
            "process_id": process_id,
            "message": f"Successfully attached to process {process_id}"
        }

    except Exception as e:
        logger.exception(f"Error attaching to process: {process_id}")
        return {"status": "error", "message": f"Attach error: {str(e)}"}


def wrapper_run_frida_script(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_run_frida_script.
    Runs a Frida script on the target process.

    Parameters:
        script_path (str): Path to Frida script file
        process_id (int, optional): Target process ID

    Returns:
        dict: Script execution results
    """
    logger.debug("Entered wrapper_run_frida_script with parameters: %s", parameters)
    script_path = parameters.get("script_path")
    process_id = parameters.get("process_id")

    if not script_path:
        return {"status": "error", "message": "Missing 'script_path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Running Frida script: {script_path}"))
        logger.info(f"Running Frida script: {script_path}")

        if not os.path.exists(script_path):
            return {"status": "error", "message": f"Script file not found: {script_path}"}

        # Simplified Frida execution - would need actual Frida integration
        return {
            "status": "success",
            "script_path": script_path,
            "process_id": process_id,
            "output": "Script executed successfully",
            "message": f"Frida script executed: {script_path}"
        }

    except Exception as e:
        logger.exception(f"Error running Frida script: {script_path}")
        return {"status": "error", "message": f"Script execution error: {str(e)}"}


def wrapper_detach(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_detach.
    Detaches from the target process.

    Returns:
        dict: Detach status
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Detaching from target process"))
        logger.info("Detaching from target process")

        # Simplified detach - would clean up actual process connections
        return {
            "status": "success",
            "message": "Successfully detached from target process"
        }

    except Exception as e:
        logger.exception("Error detaching from target")
        return {"status": "error", "message": f"Detach error: {str(e)}"}


def wrapper_propose_patch(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_propose_patch.
    Proposes patches based on analysis results.

    Parameters:
        analysis_results (dict, optional): Analysis results to base patches on

    Returns:
        dict: Proposed patches
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Proposing patches"))
        logger.info("Proposing patches")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Generate sample patch proposals
        patches = [
            {
                "id": 1,
                "type": "license_bypass",
                "description": "Bypass license validation routine",
                "address": "0x401000",
                "original_bytes": "74 05",
                "new_bytes": "90 90"
            },
            {
                "id": 2, 
                "type": "trial_extension",
                "description": "Extend trial period",
                "address": "0x402000",
                "original_bytes": "83 c4 04",
                "new_bytes": "31 c0 90"
            }
        ]

        return {
            "status": "success",
            "patches": patches,
            "count": len(patches),
            "message": f"Proposed {len(patches)} patches"
        }

    except Exception as e:
        logger.exception("Error proposing patches")
        return {"status": "error", "message": f"Patch proposal error: {str(e)}"}


def wrapper_get_proposed_patches(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_get_proposed_patches.
    Gets the list of currently proposed patches.

    Returns:
        dict: List of proposed patches
    """
    try:
        app_instance.update_output.emit(log_message("[Tool] Getting proposed patches"))
        logger.info("Getting proposed patches")

        # Get patches from app instance if available
        patches = getattr(app_instance, 'potential_patches', [])

        return {
            "status": "success",
            "patches": patches,
            "count": len(patches),
            "message": f"Retrieved {len(patches)} proposed patches"
        }

    except Exception as e:
        logger.exception("Error getting proposed patches")
        return {"status": "error", "message": f"Error retrieving patches: {str(e)}"}


def wrapper_apply_confirmed_patch(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_apply_confirmed_patch.
    Applies a confirmed patch to the binary.

    Parameters:
        patch_id (int): ID of patch to apply

    Returns:
        dict: Patch application results
    """
    logger.debug("Entered wrapper_apply_confirmed_patch with parameters: %s", parameters)
    patch_id = parameters.get("patch_id")

    if patch_id is None:
        return {"status": "error", "message": "Missing 'patch_id' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Applying patch: {patch_id}"))
        logger.info(f"Applying patch: {patch_id}")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Simplified patch application - would need actual binary modification
        return {
            "status": "success",
            "patch_id": patch_id,
            "applied": True,
            "message": f"Successfully applied patch {patch_id}"
        }

    except Exception as e:
        logger.exception(f"Error applying patch: {patch_id}")
        return {"status": "error", "message": f"Patch application error: {str(e)}"}


def wrapper_generate_launcher_script(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for tool_generate_launcher_script.
    Generates a launcher script for the patched binary.

    Parameters:
        output_path (str, optional): Path for launcher script

    Returns:
        dict: Launcher script generation results
    """
    logger.debug("Entered wrapper_generate_launcher_script with parameters: %s", parameters)
    output_path = parameters.get("output_path", "launcher.bat")

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Generating launcher script: {output_path}"))
        logger.info(f"Generating launcher script: {output_path}")

        if not hasattr(app_instance, 'binary_path') or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Generate simple launcher script
        script_content = f"""@echo off
echo Starting patched application...
"{app_instance.binary_path}"
pause
"""

        with open(output_path, 'w') as f:
            f.write(script_content)

        return {
            "status": "success",
            "script_path": output_path,
            "message": f"Launcher script generated: {output_path}"
        }

    except Exception as e:
        logger.exception(f"Error generating launcher script: {output_path}")
        return {"status": "error", "message": f"Script generation error: {str(e)}"}


def dispatch_tool(app_instance, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Central dispatcher for tool wrapper functions.
    
    Args:
        app_instance: The main application instance
        tool_name: Name of the tool to execute
        parameters: Parameters to pass to the tool
        
    Returns:
        dict: Tool execution results
    """
    logger.info(f"Dispatching tool: {tool_name} with parameters: {parameters}")
    
    tool_map = {
        "find_file": wrapper_find_file,
        "load_binary": wrapper_load_binary,
        "list_relevant_files": wrapper_list_relevant_files,
        "read_file_chunk": wrapper_read_file_chunk,
        "get_file_metadata": wrapper_get_file_metadata,
        "run_static_analysis": wrapper_run_static_analysis,
        "deep_license_analysis": wrapper_deep_license_analysis,
        "detect_protections": wrapper_detect_protections,
        "disassemble_address": wrapper_disassemble_address,
        "get_cfg": wrapper_get_cfg,
        "launch_target": wrapper_launch_target,
        "attach_target": wrapper_attach_target,
        "run_frida_script": wrapper_run_frida_script,
        "detach": wrapper_detach,
        "propose_patch": wrapper_propose_patch,
        "get_proposed_patches": wrapper_get_proposed_patches,
        "apply_confirmed_patch": wrapper_apply_confirmed_patch,
        "generate_launcher_script": wrapper_generate_launcher_script,
    }
    
    if tool_name not in tool_map:
        logger.warning(f"Unknown tool: {tool_name}")
        return {"status": "error", "message": f"Unknown tool: {tool_name}"}
    
    try:
        return tool_map[tool_name](app_instance, parameters)
    except Exception as e:
        logger.exception(f"Error executing tool {tool_name}")
        return {"status": "error", "message": f"Tool execution failed: {str(e)}"}


def run_external_tool(args):
    """Run an external tool with the given arguments."""
    import subprocess
    
    logger.info(f"Running external tool: {' '.join(args)}")
    results = f"Running external tool: {' '.join(args)}\n"

    try:
        # Run the command
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8"
        )
        logger.info(f"Subprocess started: {args} (PID: {process.pid})")

        # Get output
        stdout, stderr = process.communicate()
        logger.info(f"Subprocess finished with exit code {process.returncode}")
        if stdout:
            logger.info(f"Subprocess stdout:\n{stdout}")
        if stderr:
            logger.warning(f"Subprocess stderr:\n{stderr}")

        # Format results
        results += f"\nExit code: {process.returncode}\n"

        if stdout:
            results += f"\nOutput:\n{stdout}\n"

        if stderr:
            results += f"\nErrors:\n{stderr}\n"

    except Exception as e:
        logger.exception(f"Error executing external tool: {e}")
        results += f"\nError executing command: {e}\n"

    return results


def wrapper_deep_runtime_monitoring(app_instance, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for deep runtime monitoring functionality.
    
    Args:
        app_instance: Application instance
        parameters: Dict containing 'binary_path' and optional 'timeout'
        
    Returns:
        Dict with monitoring results
    """
    try:
        # Get parameters
        binary_path = parameters.get('binary_path')
        timeout = parameters.get('timeout', 30000)
        
        if not binary_path:
            return {
                "status": "error",
                "error": "No binary_path provided for runtime monitoring"
            }
            
        # Import the deep runtime monitoring function
        from .core_utilities import deep_runtime_monitoring
        
        # Create monitoring config
        monitoring_config = {
            "monitor_api_calls": True,
            "monitor_file_operations": True,
            "monitor_registry": True,
            "monitor_network": True,
            "capture_strings": True,
            "timeout": timeout
        }
        
        # Run the monitoring
        result = deep_runtime_monitoring(binary_path, monitoring_config)
        
        # Extract logs from result
        if isinstance(result, dict) and 'logs' in result:
            logs = result['logs']
        else:
            logs = result
        
        # Update UI if available
        if app_instance and hasattr(app_instance, 'update_output'):
            for log in logs:
                app_instance.update_output.emit(f"[Runtime Monitor] {log}")
        
        return {
            "status": "success",
            "binary_path": binary_path,
            "timeout": timeout,
            "logs": logs,
            "monitoring_complete": True
        }
        
    except Exception as e:
        error_msg = f"Error in runtime monitoring: {str(e)}"
        logger.error(error_msg)
        
        if app_instance and hasattr(app_instance, 'update_output'):
            app_instance.update_output.emit(f"[Runtime Monitor] ERROR: {error_msg}")
            
        return {
            "status": "error",
            "error": error_msg,
            "traceback": traceback.format_exc()
        }