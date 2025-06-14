"""
Common Ghidra plugin execution utilities to avoid code duplication.
"""

import os
import subprocess
from .logger import log_message


def run_ghidra_plugin(ghidra_path, temp_dir, project_name, binary_path, plugin_dir, plugin_file, app=None, overwrite=True):
    """
    Common function to run a Ghidra plugin.
    
    Args:
        ghidra_path: Path to Ghidra executable
        temp_dir: Temporary directory for project
        project_name: Name of the Ghidra project
        binary_path: Path to the binary to analyze
        plugin_dir: Directory containing the plugin
        plugin_file: Plugin filename
        app: Optional app instance for UI updates
        overwrite: Whether to overwrite existing project
        
    Returns:
        tuple: (returncode, stdout, stderr)
    """
    if app:
        app.update_output.emit(log_message(
            "[Plugin] Setting up Ghidra project..."))
    
    # Build the command
    from .ghidra_utils import build_ghidra_command
    cmd = build_ghidra_command(
        ghidra_path,
        temp_dir,
        project_name,
        binary_path,
        plugin_dir,
        plugin_file,
        overwrite=overwrite
    )
    
    if app:
        app.update_output.emit(log_message(
            "[Plugin] Running Ghidra headless analyzer..."))
    
    # Run Ghidra
    try:
        from .process_helpers import run_ghidra_process
        returncode, stdout, stderr = run_ghidra_process(cmd)
        return returncode, stdout, stderr
    except ImportError:
        # Fallback to common subprocess utility
        from .subprocess_utils import run_subprocess
        return run_subprocess(cmd, cwd=os.path.dirname(ghidra_path) if ghidra_path else None)


def get_ghidra_output_messages(returncode, stdout, stderr, app=None):
    """
    Process and format Ghidra output messages.
    
    Args:
        returncode: Process return code
        stdout: Standard output
        stderr: Standard error
        app: Optional app instance for UI updates
        
    Returns:
        list: List of formatted messages
    """
    messages = []
    
    if returncode == 0:
        messages.append("[Plugin] Ghidra analysis completed successfully")
        if stdout:
            messages.append(f"[Plugin] Output: {stdout[:500]}{'...' if len(stdout) > 500 else ''}")
    else:
        messages.append(f"[Plugin] Ghidra analysis failed with code {returncode}")
        if stderr:
            messages.append(f"[Plugin] Error: {stderr[:500]}{'...' if len(stderr) > 500 else ''}")
    
    # Emit messages if app provided
    if app:
        for message in messages:
            app.update_output.emit(log_message(message))
    
    return messages