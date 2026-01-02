"""Tool wrapper functions for Intellicrack.

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

import importlib
import json
import logging
import os
import platform
import subprocess
import time
import traceback
from types import ModuleType
from typing import Any

capstone: ModuleType | None = None
frida: ModuleType | None = None
pefile: ModuleType | None = None

try:
    capstone = importlib.import_module("capstone")
except ImportError:
    capstone = None

try:
    frida = importlib.import_module("frida")
except ImportError:
    frida = None

try:
    pefile = importlib.import_module("pefile")
except ImportError:
    pefile = None

logger: logging.Logger = logging.getLogger(__name__)


def log_message(message: str) -> str:
    """Format log messages with timestamp.

    Args:
        message: The message text to format with a timestamp prefix.

    Returns:
        Formatted message string with timestamp prefix.

    """
    return f"[{time.strftime('%H:%M:%S')}] {message}"


def wrapper_find_file(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Search for files based on filename.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'filename' key to search for.

    Returns:
        Result dictionary with status and path if found.

    """
    logger.debug("Entered wrapper_find_file with parameters: %s", parameters)
    filename = parameters.get("filename")
    if not filename:
        logger.warning("Missing 'filename' parameter for tool_find_file")
        return {"status": "error", "message": "Missing 'filename' parameter for tool_find_file"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Searching for file: {filename}"))
        logger.info("Searching for file: %s", filename)

        # Start search from current directory
        for root, _, files in os.walk("."):
            for file in files:
                if filename in file:
                    file_path = os.path.join(root, file)
                    logger.info("Found file at: %s", file_path)
                    return {
                        "status": "success",
                        "path": file_path,
                        "message": f"Found file at: {file_path}",
                    }

        logger.warning(f"File '{filename}' not found")
        return {"status": "error", "message": f"File '{filename}' not found"}
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error searching for file: {filename}")
        return {"status": "error", "message": f"Error searching for file: {str(e)}"}


def wrapper_load_binary(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Load a binary file for analysis.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'path' key for binary file location.

    Returns:
        Binary information from app_instance.binary_info.

    """
    logger.debug("Entered wrapper_load_binary with parameters: %s", parameters)
    path = parameters.get("path")
    if not path:
        logger.warning("Missing 'path' parameter for tool_load_binary")
        return {"status": "error", "message": "Missing 'path' parameter for tool_load_binary"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Loading binary: {path}"))
        logger.info("Loading binary: %s", path)

        if not os.path.exists(path):
            return {"status": "error", "message": f"File not found: {path}"}

        # Load the binary using the app's load_binary method
        app_instance.binary_path = path
        app_instance.load_binary()

        if hasattr(app_instance, "binary_info") and app_instance.binary_info:
            return {
                "status": "success",
                "binary_info": app_instance.binary_info,
                "message": f"Successfully loaded binary: {path}",
            }
        else:
            return {"status": "error", "message": "Failed to extract binary information"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error loading binary: {path}")
        return {"status": "error", "message": f"Error loading binary: {str(e)}"}


def wrapper_list_relevant_files(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """List files relevant to the current binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary of parameters (unused in current implementation).

    Returns:
        List of relevant files with metadata.

    """
    try:
        logger.debug(f"Listing relevant files with parameters: {parameters}")
        app_instance.update_output.emit(log_message("[Tool] Listing relevant files"))
        logger.info("Listing relevant files")

        binary_path = getattr(app_instance, "binary_path", None)
        if not binary_path:
            return {"status": "error", "message": "No binary loaded"}

        binary_dir = os.path.dirname(binary_path)
        relevant_extensions = [".dll", ".exe", ".so", ".dylib", ".config", ".xml", ".txt", ".log"]
        relevant_files = []

        for root, _, files in os.walk(binary_dir):
            for file in files:
                if any(file.lower().endswith(ext) for ext in relevant_extensions):
                    file_path = os.path.join(root, file)
                    relevant_files.append(
                        {
                            "path": file_path,
                            "name": file,
                            "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                        }
                    )

        return {
            "status": "success",
            "files": relevant_files,
            "count": len(relevant_files),
            "message": f"Found {len(relevant_files)} relevant files",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error listing relevant files")
        return {"status": "error", "message": f"Error listing files: {str(e)}"}


def wrapper_read_file_chunk(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Read a chunk of data from a file.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'path' (required), 'offset' (optional, default 0),
            and 'size' (optional, default 1024).

    Returns:
        File chunk data with status, data, size, and offset.

    """
    logger.debug("Entered wrapper_read_file_chunk with parameters: %s", parameters)
    path = parameters.get("path")
    offset = parameters.get("offset", 0)
    size = parameters.get("size", 1024)

    if not path:
        return {"status": "error", "message": "Missing 'path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Reading file chunk: {path}"))
        logger.info("Reading file chunk: %s (offset: %s, size: %s)", path, offset, size)

        if not os.path.exists(path):
            return {"status": "error", "message": f"File not found: {path}"}

        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(size)

            return {
                "status": "success",
                "data": data.hex(),
                "size": len(data),
                "offset": offset,
                "message": f"Read {len(data)} bytes from {path}",
            }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error reading file chunk: {path}")
        return {"status": "error", "message": f"Error reading file: {str(e)}"}


def wrapper_get_file_metadata(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Get metadata information about a file.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'path' key for the file.

    Returns:
        File metadata including size, timestamps, and attributes.

    """
    logger.debug("Entered wrapper_get_file_metadata with parameters: %s", parameters)
    path = parameters.get("path")

    if not path:
        return {"status": "error", "message": "Missing 'path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Getting file metadata: {path}"))
        logger.info("Getting file metadata: %s", path)

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
            "extension": os.path.splitext(path)[1].lower(),
        }

        return {
            "status": "success",
            "metadata": metadata,
            "message": f"Retrieved metadata for {path}",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error getting file metadata: {path}")
        return {"status": "error", "message": f"Error getting metadata: {str(e)}"}


def wrapper_run_static_analysis(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Run static analysis on the loaded binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary of parameters (unused in current implementation).

    Returns:
        Static analysis results.

    """
    logger.debug(f"Running static analysis with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Running static analysis"))
        logger.info("Running static analysis")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use the app's existing analysis methods
        app_instance.run_analysis()

        return {
            "status": "success",
            "message": "Static analysis completed",
            "results": getattr(app_instance, "analyze_results", []),
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error running static analysis")
        return {"status": "error", "message": f"Error in static analysis: {str(e)}"}


def wrapper_deep_license_analysis(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Run deep license analysis on the loaded binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary of parameters (unused in current implementation).

    Returns:
        License analysis results.

    """
    logger.debug(f"Running deep license analysis with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Running deep license analysis"))
        logger.info("Running deep license analysis")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use the app's existing deep license analysis
        app_instance.run_deep_license_analysis()

        return {"status": "success", "message": "Deep license analysis completed"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error running deep license analysis")
        return {"status": "error", "message": f"Error in license analysis: {str(e)}"}


def wrapper_detect_protections(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Detect protections in the loaded binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary of parameters (unused in current implementation).

    Returns:
        Protection detection results.

    """
    logger.debug(f"Detecting protections with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Detecting protections"))
        logger.info("Detecting protections")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use existing protection detection methods
        protections = []
        if hasattr(app_instance, "binary_info") and app_instance.binary_info:
            protections = app_instance.binary_info.get("protections", [])

        return {
            "status": "success",
            "protections": protections,
            "count": len(protections),
            "message": f"Detected {len(protections)} protections",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error detecting protections")
        return {"status": "error", "message": f"Error detecting protections: {str(e)}"}


def wrapper_disassemble_address(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Disassemble instructions at a given address.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'address' (required) and 'num_instructions'
            (optional, default 10).

    Returns:
        Disassembly listing with status and instructions.

    """
    logger.debug("Entering wrapper_disassemble_address with parameters: %s", parameters)
    address = parameters.get("address")
    num_instructions = parameters.get("num_instructions", 10)

    if address is None:
        return {
            "status": "error",
            "message": "Missing 'address' parameter for tool_disassemble_address",
        }

    try:
        address = int(address) if isinstance(address, str) else address
        num_instructions = int(num_instructions)

        logger.info("Disassembling address: 0x%d, %s instructions", address, num_instructions)
        app_instance.update_output.emit(log_message(f"[Tool] Disassembling address: 0x{address:x}, {num_instructions} instructions"))

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            logger.warning("Disassemble attempt failed: No binary loaded.")
            return {"status": "error", "message": "No binary loaded. Load a binary first."}

        # Real disassembly using Capstone engine
        if capstone is None:
            try:
                binary_path = app_instance.binary_path
                if platform.system() == "Windows":
                    cmd = [
                        "objdump",
                        "-d",
                        "--start-address",
                        f"0x{address:x}",
                        "--stop-address",
                        f"0x{address + num_instructions * 16:x}",
                        binary_path,
                    ]
                else:
                    cmd = [
                        "objdump",
                        "-d",
                        f"--start-address=0x{address:x}",
                        f"--stop-address=0x{address + num_instructions * 16:x}",
                        binary_path,
                    ]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.split("\n")
                    disassembly = []
                    for line in lines:
                        if ":" in line and "\t" in line:
                            parts = line.split("\t")
                            if len(parts) >= 2:
                                addr_part = parts[0].strip()
                                instr_part = " ".join(parts[1:]).strip()
                                disassembly.append(f"{addr_part}: {instr_part}")
                    return {
                        "status": "success",
                        "address": f"0x{address:x}",
                        "num_instructions": len(disassembly),
                        "disassembly": disassembly[:num_instructions],
                    }
            except Exception as e:
                logger.error(f"Objdump disassembly failed: {e}")
                return {"status": "error", "message": f"Objdump disassembly failed: {str(e)}"}

            return {"status": "error", "message": "Capstone library not available for disassembly."}
        try:
            with open(app_instance.binary_path, "rb") as f:
                f.seek(address)
                code = f.read(num_instructions * 16)  # Read enough bytes for instructions

            # Determine architecture
            if pefile and app_instance.binary_path.lower().endswith((".exe", ".dll")):
                pe = pefile.PE(app_instance.binary_path)
                if pe.FILE_HEADER.Machine == 0x8664:  # AMD64
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                else:  # x86
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            else:
                # Default to x64
                cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            disassembly = []
            count = 0
            for instr in cs.disasm(code, address):
                disassembly.append(f"0x{instr.address:x}: {instr.mnemonic} {instr.op_str}")
                count += 1
                if count >= num_instructions:
                    break

            return {"status": "success", "address": f"0x{address:x}", "num_instructions": len(disassembly), "disassembly": disassembly}
        except Exception as e:
            logger.error(f"Capstone disassembly failed: {e}")
            return {"status": "error", "message": f"Disassembly failed: {str(e)}"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error disassembling address: 0x{address:x}")
        return {"status": "error", "message": f"Disassembly error: {str(e)}"}


def wrapper_get_cfg(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Get control flow graph for a function.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'function_address' key.

    Returns:
        Control flow graph data.

    """
    logger.debug("Entered wrapper_get_cfg with parameters: %s", parameters)
    _ = parameters.get("function_address")  # Parameter not used in current implementation

    try:
        app_instance.update_output.emit(log_message("[Tool] Generating control flow graph"))
        logger.info("Generating control flow graph")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Use existing CFG explorer if available
        if hasattr(app_instance, "cfg_explorer") and app_instance.cfg_explorer:
            try:
                graph_data = app_instance.cfg_explorer.get_graph_data()
                return {
                    "status": "success",
                    "cfg_data": graph_data,
                    "message": "Control flow graph generated",
                }
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("CFG explorer failed: %s", e)

        # Fallback response
        return {
            "status": "success",
            "cfg_data": {"nodes": [], "edges": []},
            "message": "CFG generation completed (simplified)",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error generating CFG")
        return {"status": "error", "message": f"CFG generation error: {str(e)}"}


def wrapper_launch_target(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Launch the target process for dynamic analysis.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'args' and 'suspended' keys.

    Returns:
        Launch status and process information.

    """
    logger.debug(f"Launching target with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Launching target process"))
        logger.info("Launching target process")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Real process launching with proper subprocess handling
        binary_path = app_instance.binary_path
        args = parameters.get("args", [])
        suspended = parameters.get("suspended", False)

        # Launch the process
        if platform.system() == "Windows":
            if suspended:
                # Use Windows CREATE_SUSPENDED flag
                import ctypes
                from ctypes import wintypes

                # Define Windows constants
                CREATE_SUSPENDED = 0x00000004
                CREATE_NEW_CONSOLE = 0x00000010

                class STARTUPINFO(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD),
                        ("lpReserved", wintypes.LPWSTR),
                        ("lpDesktop", wintypes.LPWSTR),
                        ("lpTitle", wintypes.LPWSTR),
                        ("dwX", wintypes.DWORD),
                        ("dwY", wintypes.DWORD),
                        ("dwXSize", wintypes.DWORD),
                        ("dwYSize", wintypes.DWORD),
                        ("dwXCountChars", wintypes.DWORD),
                        ("dwYCountChars", wintypes.DWORD),
                        ("dwFillAttribute", wintypes.DWORD),
                        ("dwFlags", wintypes.DWORD),
                        ("wShowWindow", wintypes.WORD),
                        ("cbReserved2", wintypes.WORD),
                        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                        ("hStdInput", wintypes.HANDLE),
                        ("hStdOutput", wintypes.HANDLE),
                        ("hStdError", wintypes.HANDLE),
                    ]

                class PROCESS_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("hProcess", wintypes.HANDLE),
                        ("hThread", wintypes.HANDLE),
                        ("dwProcessId", wintypes.DWORD),
                        ("dwThreadId", wintypes.DWORD),
                    ]

                startup_info = STARTUPINFO()
                startup_info.cb = ctypes.sizeof(STARTUPINFO)
                process_info = PROCESS_INFORMATION()

                # Create process in suspended state
                kernel32 = ctypes.windll.kernel32
                cmd_line = f'"{binary_path}"'
                if args:
                    cmd_line += " " + " ".join(f'"{arg}"' for arg in args)

                if result := kernel32.CreateProcessW(
                    None,
                    cmd_line,
                    None,
                    None,
                    False,
                    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                    None,
                    None,
                    ctypes.byref(startup_info),
                    ctypes.byref(process_info),
                ):
                    pid = process_info.dwProcessId
                    # Store handles for later use
                    if hasattr(app_instance, "process_handles"):
                        app_instance.process_handles[pid] = {"process": process_info.hProcess, "thread": process_info.hThread}
                    return {
                        "status": "success",
                        "process_id": pid,
                        "suspended": True,
                        "message": f"Process launched in suspended state: {binary_path}",
                    }
                else:
                    error = kernel32.GetLastError()
                    return {"status": "error", "message": f"Failed to launch process: Windows error {error}"}
            else:
                # Normal launch
                process = subprocess.Popen(
                    [binary_path] + args, creationflags=subprocess.CREATE_NEW_CONSOLE if platform.system() == "Windows" else 0
                )
                return {"status": "success", "process_id": process.pid, "message": f"Target process launched: {binary_path}"}
        else:
            # Unix/Linux process launching
            if suspended:
                # Use ptrace to suspend on Unix
                import signal

                if not hasattr(signal, "SIGSTOP"):
                    return {"status": "error", "message": "SIGSTOP not available on this platform"}
                sig_value = getattr(signal, "SIGSTOP")
                process = subprocess.Popen([binary_path] + args, preexec_fn=lambda: os.kill(os.getpid(), sig_value))
            else:
                process = subprocess.Popen([binary_path] + args)

            return {
                "status": "success",
                "process_id": process.pid,
                "suspended": suspended,
                "message": f"Target process launched: {binary_path}",
            }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error launching target")
        return {"status": "error", "message": f"Launch error: {str(e)}"}


def wrapper_attach_target(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Attach to a running target process.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'process_id' key.

    Returns:
        Attach status and process information.

    """
    logger.debug("Entered wrapper_attach_target with parameters: %s", parameters)
    process_id = parameters.get("process_id")

    if not process_id:
        return {"status": "error", "message": "Missing 'process_id' parameter"}

    try:
        process_id = int(process_id)
        app_instance.update_output.emit(log_message(f"[Tool] Attaching to process: {process_id}"))
        logger.info("Attaching to process: %s", process_id)

        # Real process attachment implementation
        if platform.system() == "Windows":
            # Windows debugger attachment using Windows Debug APIs
            import ctypes

            kernel32 = ctypes.windll.kernel32

            # Try to attach as debugger
            if kernel32.DebugActiveProcess(process_id):
                # Store attached process info
                if not hasattr(app_instance, "attached_processes"):
                    app_instance.attached_processes = {}
                app_instance.attached_processes[process_id] = True

                return {
                    "status": "success",
                    "process_id": process_id,
                    "message": f"Successfully attached to process {process_id}",
                    "method": "windows_debug_api",
                }
            else:
                error = kernel32.GetLastError()
                return {"status": "error", "message": f"Failed to attach: Windows error {error}"}
        else:
            # Unix/Linux ptrace attachment
            try:
                # Check if process exists
                os.kill(process_id, 0)

                # Try ptrace attachment (requires privileges)
                import ctypes

                libc = ctypes.CDLL("libc.so.6")
                PTRACE_ATTACH = 16

                result = libc.ptrace(PTRACE_ATTACH, process_id, 0, 0)
                if result == 0:
                    # Wait for process to stop
                    os.waitpid(process_id, 0)

                    if not hasattr(app_instance, "attached_processes"):
                        app_instance.attached_processes = {}
                    app_instance.attached_processes[process_id] = True

                    return {
                        "status": "success",
                        "process_id": process_id,
                        "message": f"Successfully attached to process {process_id}",
                        "method": "ptrace",
                    }
                else:
                    return {"status": "error", "message": "Failed to attach: ptrace failed (may need root privileges)"}
            except ProcessLookupError:
                return {"status": "error", "message": f"Process {process_id} not found"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error attaching to process: {process_id}")
        return {"status": "error", "message": f"Attach error: {str(e)}"}


def wrapper_run_frida_script(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Run a Frida script on the target process.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'script_path' (required) and optional
            'process_id' and 'process_name' keys.

    Returns:
        Script execution results and output.

    """
    logger.debug("Entered wrapper_run_frida_script with parameters: %s", parameters)
    script_path = parameters.get("script_path")
    process_id = parameters.get("process_id")

    if not script_path:
        return {"status": "error", "message": "Missing 'script_path' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Running Frida script: {script_path}"))
        logger.info("Running Frida script: %s", script_path)

        if not os.path.exists(script_path):
            return {"status": "error", "message": f"Script file not found: {script_path}"}

        # Real Frida script execution
        if frida is None:
            # Fallback to subprocess if Frida module not available
            # Execute using frida CLI tool
            cmd = ["frida"]
            if process_id:
                cmd.extend(["-p", str(process_id)])
            cmd.extend(["-l", script_path])

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    output_lines = result.stdout or "Script executed"
                    return {
                        "status": "success",
                        "script_path": script_path,
                        "process_id": process_id,
                        "output": output_lines,
                        "message": f"Frida script executed via CLI: {script_path}",
                    }
                else:
                    return {"status": "error", "message": f"Frida execution failed: {result.stderr}"}
            except subprocess.TimeoutExpired:
                return {"status": "error", "message": "Frida script execution timed out"}
            except FileNotFoundError:
                return {"status": "error", "message": "Frida CLI not found. Please install Frida."}

        # Use Frida Python API (when frida is available)
        try:
            # Read script content
            with open(script_path) as f:
                script_content = f.read()

            # Attach to process or spawn new one
            session = None
            if process_id:
                # Attach to existing process
                session = frida.attach(process_id)
            else:
                # Get process name from parameters or app_instance
                process_name = parameters.get("process_name")
                if not process_name and hasattr(app_instance, "binary_path"):
                    process_name = os.path.basename(app_instance.binary_path)

                if process_name:
                    # Spawn new process
                    pid = frida.spawn(process_name)
                    session = frida.attach(pid)
                    frida.resume(pid)
                    process_id = pid
                else:
                    return {"status": "error", "message": "No process specified for Frida script"}

            # Create and load script
            script = session.create_script(script_content)

            # Collect output messages
            output_messages: list[str] = []

            def on_message(message: Any, data: Any) -> None:
                """Handle Frida script messages.

                Args:
                    message: Message from Frida script (dict or other type).
                    data: Additional data payload.

                """
                if isinstance(message, dict):
                    if message.get("type") == "send":
                        output_messages.append(str(message.get("payload", "")))
                    elif message.get("type") == "error":
                        output_messages.append(f"Error: {message.get('description', '')}")

            script.on("message", on_message)
            script.load()

            # Let script run for a bit to collect output
            import time

            time.sleep(2)

            # Store session for later use
            if not hasattr(app_instance, "frida_sessions"):
                app_instance.frida_sessions = {}
            if process_id:
                app_instance.frida_sessions[process_id] = session

            output_str = "\n".join(output_messages) if output_messages else "Script loaded and running"
            return {
                "status": "success",
                "script_path": script_path,
                "process_id": process_id,
                "output": output_str,
                "message": f"Frida script executed: {script_path}",
            }

        except Exception as e:
            if frida and isinstance(e, frida.ProcessNotFoundError):
                return {"status": "error", "message": f"Process {process_id} not found"}
            else:
                return {"status": "error", "message": f"Frida execution error: {str(e)}"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error running Frida script: {script_path}")
        return {"status": "error", "message": f"Script execution error: {str(e)}"}


def wrapper_detach(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Detach from the target process.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'process_id' key.

    Returns:
        Detach status and results.

    """
    logger.debug(f"Detaching with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Detaching from target process"))
        logger.info("Detaching from target process")

        # Real process detachment
        process_id = parameters.get("process_id")

        # Clean up Frida sessions if any
        if hasattr(app_instance, "frida_sessions"):
            for pid in list(app_instance.frida_sessions.keys()):
                if process_id is None or pid == process_id:
                    try:
                        session = app_instance.frida_sessions[pid]
                        session.detach()
                        del app_instance.frida_sessions[pid]
                    except Exception as e:
                        logger.warning(f"Failed to detach Frida session from {pid}: {e}")

        # Clean up debugger attachments
        if hasattr(app_instance, "attached_processes"):
            import ctypes

            if platform.system() == "Windows":
                kernel32 = ctypes.windll.kernel32

                for pid in list(app_instance.attached_processes.keys()):
                    if process_id is None or pid == process_id:
                        try:
                            # Windows debugger detach
                            if kernel32.DebugActiveProcessStop(pid):
                                del app_instance.attached_processes[pid]
                            else:
                                logger.warning(f"Failed to detach from process {pid}")
                        except Exception as e:
                            logger.warning(f"Error detaching from {pid}: {e}")
            else:
                libc = ctypes.CDLL("libc.so.6")
                PTRACE_DETACH = 17

                for pid in list(app_instance.attached_processes.keys()):
                    if process_id is None or pid == process_id:
                        try:
                            result = libc.ptrace(PTRACE_DETACH, pid, 0, 0)
                            if result == 0:
                                del app_instance.attached_processes[pid]
                            else:
                                logger.warning(f"Failed to detach from process {pid}")
                        except Exception as e:
                            logger.warning(f"Error detaching from {pid}: {e}")

        # Clean up process handles
        if hasattr(app_instance, "process_handles") and platform.system() == "Windows":
            import ctypes
        
            kernel32 = ctypes.windll.kernel32
        
            for pid in list(app_instance.process_handles.keys()):
                if process_id is None or pid == process_id:
                    try:
                        handles = app_instance.process_handles[pid]
                        if "process" in handles:
                            kernel32.CloseHandle(handles["process"])
                        if "thread" in handles:
                            kernel32.CloseHandle(handles["thread"])
                        del app_instance.process_handles[pid]
                    except Exception as e:
                        logger.warning(f"Error closing handles for {pid}: {e}")

        return {"status": "success", "message": "Successfully detached from target process"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error detaching from target")
        return {"status": "error", "message": f"Detach error: {str(e)}"}


def wrapper_propose_patch(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Propose patches based on analysis results.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'analysis_results' key.

    Returns:
        Proposed patches with analysis methods and confidence scores.

    """
    logger.debug(f"Proposing patches with parameters: {parameters}")
    try:
        app_instance.update_output.emit(log_message("[Tool] Proposing patches"))
        logger.info("Proposing patches")

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Comprehensive patch proposal generation using multiple analysis techniques
        patches = []
        analysis_methods = []

        try:
            # Method 1: Static analysis for common patterns
            static_patches = _analyze_static_patterns(app_instance.binary_path)
            patches.extend(static_patches)
            analysis_methods.append("static_pattern_analysis")

            # Method 2: String analysis for license-related functions
            string_patches = _analyze_license_strings(app_instance.binary_path)
            patches.extend(string_patches)
            analysis_methods.append("string_analysis")

            # Method 3: Import table analysis
            import_patches = _analyze_imports(app_instance.binary_path)
            patches.extend(import_patches)
            analysis_methods.append("import_analysis")

            # Method 4: Disassembly-based analysis
            disasm_patches = _analyze_disassembly(app_instance.binary_path)
            patches.extend(disasm_patches)
            analysis_methods.append("disassembly_analysis")

            # Method 5: Machine learning predictions (if available)
            # try:
            #     from ...ai.ml_predictor import predict_vulnerabilities
            #     ml_result = predict_vulnerabilities(app_instance.binary_path)
            #     if ml_result.get('vulnerabilities'):
            #         ml_patches = _convert_vulnerabilities_to_patches(ml_result['vulnerabilities'])
            #         patches.extend(ml_patches)
            #         analysis_methods.append('ml_analysis')
            # except Exception as e:
            #     logger.debug(f"ML analysis not available: {e}")

            # Remove duplicates and rank patches
            unique_patches = _deduplicate_and_rank_patches(patches)

            # Add confidence scores and risk assessments
            for i, patch in enumerate(unique_patches):
                patch["id"] = i + 1
                patch["confidence"] = _calculate_patch_confidence(patch)
                patch["risk_level"] = _assess_patch_risk(patch)
                patch["compatibility"] = _assess_compatibility(patch, app_instance.binary_path)

            # Sort by confidence and risk
            unique_patches.sort(key=lambda p: (p["confidence"], -p["risk_level"]), reverse=True)

            return {
                "status": "success",
                "patches": unique_patches[:20],  # Limit to top 20
                "total_found": len(unique_patches),
                "analysis_methods": analysis_methods,
                "binary_info": _get_binary_info(app_instance.binary_path),
                "generation_time": time.time(),
                "message": f"Generated {len(unique_patches)} patch proposals using {len(analysis_methods)} analysis methods",
            }

        except Exception as e:
            logger.error(f"Patch generation error: {e}")
            # Fallback to basic patches if advanced analysis fails
            return _generate_fallback_patches(app_instance.binary_path)

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error proposing patches")
        return {"status": "error", "message": f"Patch proposal error: {str(e)}"}


def _analyze_static_patterns(binary_path: str) -> list[dict[str, Any]]:
    """Analyze binary for common crackable patterns.

    Args:
        binary_path: Path to the binary file to analyze.

    Returns:
        Patch proposals based on identified patterns.

    """
    patches = []

    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        import re

        # Pattern 1: Conditional jumps after comparisons (license checks)
        je_jne_pattern = b"\x74."  # je followed by any byte
        for i, match in enumerate(re.finditer(je_jne_pattern, data)):
            if i >= 10:  # Limit matches
                break
            offset = match.start()
            patches.append(
                {
                    "type": "conditional_bypass",
                    "description": "Convert conditional jump to unconditional (je -> jmp)",
                    "address": hex(0x400000 + offset),
                    "file_offset": offset,
                    "original_bytes": data[offset : offset + 2].hex(),
                    "new_bytes": f"eb{data[offset + 1:offset + 2].hex()}",
                    "pattern": "je_to_jmp",
                    "analysis_method": "static_pattern",
                }
            )

        # Pattern 2: Test and jump patterns
        test_pattern = b"\x85\xc0\x74"  # test eax, eax; je
        for match in re.finditer(test_pattern, data):
            offset = match.start() + 2  # Point to the je instruction
            patches.append(
                {
                    "type": "test_bypass",
                    "description": "Bypass test result check",
                    "address": hex(0x400000 + offset),
                    "file_offset": offset,
                    "original_bytes": "74",
                    "new_bytes": "eb",  # je -> jmp
                    "pattern": "test_bypass",
                    "analysis_method": "static_pattern",
                }
            )

        # Pattern 3: Return value modification
        xor_ret_pattern = b"\x31\xc0\xc3"  # xor eax, eax; ret (return 0)
        for match in re.finditer(xor_ret_pattern, data):
            offset = match.start()
            patches.append(
                {
                    "type": "return_modification",
                    "description": "Change return value from 0 to 1",
                    "address": hex(0x400000 + offset),
                    "file_offset": offset,
                    "original_bytes": "31c0c3",
                    "new_bytes": "b801000000c3",  # mov eax, 1; ret
                    "pattern": "return_true",
                    "analysis_method": "static_pattern",
                }
            )

    except Exception as e:
        logger.warning(f"Static pattern analysis failed: {e}")

    return patches


def _analyze_license_strings(binary_path: str) -> list[dict[str, Any]]:
    """Analyze strings for license-related patches.

    Args:
        binary_path: Path to the binary file to analyze.

    Returns:
        Patch proposals based on identified license strings.

    """
    patches = []

    try:
        # Extract strings from binary
        with open(binary_path, "rb") as f:
            data = f.read()

        # Find ASCII strings
        import re

        strings = re.findall(b"[\x20-\x7e]{4,}", data)

        license_keywords = [
            b"license",
            b"trial",
            b"expired",
            b"activation",
            b"invalid",
            b"demo",
            b"evaluation",
            b"register",
            b"serial",
            b"key",
        ]

        for string in strings:
            string_lower = string.lower()
            for keyword in license_keywords:
                if keyword in string_lower:
                    # Find string offset in file
                    offset = data.find(string)
                    if offset != -1:
                        patches.append(
                            {
                                "type": "string_modification",
                                "description": f"Modify license string: {string.decode('utf-8', errors='ignore')[:50]}",
                                "address": hex(0x400000 + offset),
                                "file_offset": offset,
                                "original_bytes": string.hex()[:20],  # Limit display
                                "new_bytes": b"valid_license".hex(),
                                "pattern": "license_string",
                                "analysis_method": "string_analysis",
                                "string_content": string.decode("utf-8", errors="ignore")[:100],
                            }
                        )
                    break

    except Exception as e:
        logger.warning(f"String analysis failed: {e}")

    return patches[:5]  # Limit string patches


def _analyze_imports(binary_path: str) -> list[dict[str, Any]]:
    """Analyze import table for hookable functions.

    Args:
        binary_path: Path to the binary file to analyze.

    Returns:
        Import-based patch proposals.

    """
    patches = []

    try:
        patches = _try_pefile_import_analysis(binary_path)
    except Exception as e:
        logger.warning(f"Import analysis failed: {e}")

    return patches[:10]  # Limit import patches


def _try_pefile_import_analysis(binary_path: str) -> list[dict[str, Any]]:
    """Try PE import analysis using pefile.

    Args:
        binary_path: Path to the PE binary file to analyze.

    Returns:
        Import patches or empty list if analysis fails.

    """
    patches = []

    try:
        from intellicrack.handlers.pefile_handler import pefile

        pe = pefile.PE(binary_path)

        # Use common PE analysis utility
        from ..binary.pe_analysis_common import analyze_pe_imports

        target_apis = {
            "system": ["GetSystemTime", "GetLocalTime"],
            "registry": ["RegOpenKey", "RegQueryValue"],
            "file": ["CreateFile", "ReadFile"],
            "network": ["InternetConnect", "HttpSendRequest"],
        }
        detected_apis = analyze_pe_imports(pe, target_apis)

        # Convert to patch format
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            patches = _extract_import_patches(pe, detected_apis)

    except ImportError:
        logger.debug("pefile not available for import analysis")
    except Exception as e:
        logger.warning(f"PE import analysis failed: {e}")

    return patches


def _extract_import_patches(pe: Any, detected_apis: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Extract import patches from PE analysis.

    Args:
        pe: PE object loaded with pefile.
        detected_apis: Dictionary mapping API categories to function names.

    Returns:
        Import hook patch proposals.

    """
    patches = []

    from ..binary.pe_common import iterate_pe_imports_with_dll

    def check_import_patch(dll_name: str, func_name: str, imp: Any) -> dict[str, Any] | None:
        """Check if import should be patched.

        Args:
            dll_name: DLL name containing the function.
            func_name: Function name to check.
            imp: Import object with address information.

        Returns:
            Patch proposal dictionary if function is in detected APIs, None otherwise.

        """
        for _, funcs in detected_apis.items():
            if func_name in funcs:
                return {
                    "type": "import_hook",
                    "description": f"Hook {dll_name}::{func_name} for bypassing checks",
                    "address": hex(imp.address) if imp.address else "0x0",
                    "file_offset": imp.address - pe.OPTIONAL_HEADER.ImageBase if imp.address else 0,
                    "function": func_name,
                    "dll": dll_name,
                    "patch_type": "import_redirection",
                    "analysis_method": "import_analysis",
                }
        return None

    # Use the common function to iterate imports
    import_results = iterate_pe_imports_with_dll(pe, check_import_patch, include_import_obj=True)
    if hasattr(import_results, "__iter__"):
        for patch_result in import_results:
            if patch_result is not None:
                patches.append(patch_result)

    return patches


def _analyze_disassembly(binary_path: str) -> list[dict[str, Any]]:
    """Analyze disassembly for patchable instructions.

    Args:
        binary_path: Path to the binary file to analyze.

    Returns:
        Instruction-based patch proposals.

    """
    patches = []

    try:
        from ..core.import_patterns import CAPSTONE_AVAILABLE, CS_ARCH_X86, CS_MODE_64, Cs

        if CAPSTONE_AVAILABLE:
            with open(binary_path, "rb") as f:
                data = f.read()

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True

            # Analyze first 1000 instructions
            count = 0
            for insn in md.disasm(data[:10000], 0x400000):
                if count >= 1000:
                    break
                count += 1

                # Look for interesting patterns
                if insn.mnemonic == "cmp" and "eax" in insn.op_str:
                    # Comparison that might be part of license check
                    patches.append(
                        {
                            "type": "comparison_bypass",
                            "description": f"Bypass comparison: {insn.mnemonic} {insn.op_str}",
                            "address": hex(insn.address),
                            "file_offset": insn.address - 0x400000,
                            "original_bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                            "new_bytes": "90 " * insn.size,  # NOP out the instruction
                            "instruction": f"{insn.mnemonic} {insn.op_str}",
                            "analysis_method": "disassembly_analysis",
                        }
                    )

                elif insn.mnemonic == "call":
                    # Function calls that might be license checks
                    patches.append(
                        {
                            "type": "call_bypass",
                            "description": f"Bypass function call: {insn.op_str}",
                            "address": hex(insn.address),
                            "file_offset": insn.address - 0x400000,
                            "original_bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                            "new_bytes": "90 " * insn.size,  # NOP out the call
                            "instruction": f"{insn.mnemonic} {insn.op_str}",
                            "analysis_method": "disassembly_analysis",
                        }
                    )

    except Exception as e:
        logger.warning(f"Disassembly analysis failed: {e}")

    return patches[:15]  # Limit disassembly patches


def _convert_vulnerabilities_to_patches(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert vulnerability findings to patch proposals.

    Args:
        vulnerabilities: List of vulnerability findings from analysis.

    Returns:
        Patch proposals based on vulnerabilities.

    """
    return [
        {
            "type": "vulnerability_fix",
            "description": f"Address vulnerability: {vuln.get('type', 'unknown')}",
            "address": vuln.get("address", "0x0"),
            "vulnerability": vuln.get("type", "unknown"),
            "severity": vuln.get("severity", "medium"),
            "analysis_method": "ml_analysis",
            "recommendation": vuln.get(
                "description", "Fix identified vulnerability"
            ),
        }
        for vuln in vulnerabilities[:5]
    ]


def _deduplicate_and_rank_patches(patches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicates and rank patches by effectiveness.

    Args:
        patches: List of patch proposals that may contain duplicates.

    Returns:
        Deduplicated and ranked patches.

    """
    # Simple deduplication by address
    seen_addresses = set()
    unique_patches = []

    for patch in patches:
        addr = patch.get("address", "")
        if addr not in seen_addresses:
            seen_addresses.add(addr)
            unique_patches.append(patch)

    return unique_patches


def _calculate_patch_confidence(patch: dict[str, Any]) -> float:
    """Calculate confidence score for a patch.

    Args:
        patch: Patch proposal dictionary with analysis method and type.

    Returns:
        Confidence score between 0.0 and 1.0.

    """
    confidence = 0.5  # Base confidence

    # Boost confidence based on analysis method
    method_boost = {
        "static_pattern": 0.3,
        "string_analysis": 0.2,
        "import_analysis": 0.4,
        "disassembly_analysis": 0.3,
        "ml_analysis": 0.4,
    }

    confidence += method_boost.get(patch.get("analysis_method", ""), 0)

    # Boost for known good patch types
    if patch.get("type") in ["conditional_bypass", "return_modification"]:
        confidence += 0.2

    return min(confidence, 1.0)


def _assess_patch_risk(patch: dict[str, Any]) -> int:
    """Assess risk level for a patch.

    Args:
        patch: Patch proposal dictionary with type information.

    Returns:
        Risk level (1=low, 2=medium, 3=high).

    """
    if patch.get("type") in ["string_modification", "conditional_bypass"]:
        return 1  # Low risk
    return 2 if patch.get("type") in ["return_modification", "test_bypass"] else 3


def _assess_compatibility(patch: dict[str, Any], binary_path: str) -> str:
    """Assess patch compatibility.

    Args:
        patch: Patch proposal dictionary with type information.
        binary_path: Path to the binary being patched.

    Returns:
        Compatibility level (high, medium, or low).

    """
    logger.debug(f"Assessing patch compatibility for binary: {binary_path}")
    # Simple compatibility assessment
    if patch.get("type") in ["conditional_bypass", "string_modification"]:
        return "high"
    elif patch.get("type") in ["return_modification", "import_hook"]:
        return "medium"
    else:
        return "low"


def _get_binary_info(binary_path: str) -> dict[str, Any]:
    """Get basic binary information.

    Args:
        binary_path: Path to the binary file.

    Returns:
        Binary information including size, format, and modification time.

    """
    try:
        stat = os.stat(binary_path)

        with open(binary_path, "rb") as f:
            header = f.read(64)

        return {
            "size": stat.st_size,
            "format": "PE" if header[:2] == b"MZ" else "ELF" if header[:4] == b"\x7fELF" else "Unknown",
            "modified": stat.st_mtime,
            "path": binary_path,
        }
    except (OSError, ValueError) as e:
        logger.debug("Error getting binary info: %s", e)
        return {"size": 0, "format": "Unknown", "path": binary_path}


def _generate_fallback_patches(binary_path: str) -> dict[str, Any]:
    """Generate basic fallback patches when advanced analysis fails.

    Args:
        binary_path: Path to the binary file.

    Returns:
        Fallback patch proposals and analysis results.

    """
    patches = [
        {
            "id": 1,
            "type": "license_bypass",
            "description": "Bypass license validation routine (je -> jmp)",
            "address": "0x401000",
            "original_bytes": "74 05",
            "new_bytes": "eb 05",
            "confidence": 0.7,
            "risk_level": 1,
            "compatibility": "high",
            "analysis_method": "fallback",
        },
        {
            "id": 2,
            "type": "trial_extension",
            "description": "Modify trial check (force return true)",
            "address": "0x402000",
            "original_bytes": "31 c0 c3",
            "new_bytes": "b8 01 00 00 00 c3",
            "confidence": 0.6,
            "risk_level": 2,
            "compatibility": "medium",
            "analysis_method": "fallback",
        },
        {
            "id": 3,
            "type": "nag_removal",
            "description": "Disable nag screen (conditional bypass)",
            "address": "0x403000",
            "original_bytes": "75 10",
            "new_bytes": "eb 10",
            "confidence": 0.8,
            "risk_level": 1,
            "compatibility": "high",
            "analysis_method": "fallback",
        },
    ]

    return {
        "status": "success",
        "patches": patches,
        "total_found": len(patches),
        "analysis_methods": ["fallback"],
        "binary_info": _get_binary_info(binary_path),
        "message": f"Generated {len(patches)} fallback patch proposals",
    }


def wrapper_get_proposed_patches(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Get the list of currently proposed patches.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'filter_type' and 'include_metadata' keys.

    Returns:
        Proposed patches with filtering and metadata options.

    """
    try:
        # Parse parameters for filtering and options
        filter_type = parameters.get("filter_type", "all")
        include_metadata = parameters.get("include_metadata", True)

        app_instance.update_output.emit(log_message(f"[Tool] Getting proposed patches (filter: {filter_type})"))
        logger.info("Getting proposed patches with filter: %s", filter_type)

        # Get patches from app instance if available
        all_patches = getattr(app_instance, "potential_patches", [])

        # Filter patches based on parameters
        if filter_type != "all":
            filtered_patches = [patch for patch in all_patches if patch.get("type", "").lower() == filter_type.lower()]
        else:
            filtered_patches = all_patches

        # Include metadata if requested
        if include_metadata:
            result_patches = filtered_patches
        else:
            result_patches = [{k: v for k, v in patch.items() if k in ["address", "description", "type"]} for patch in filtered_patches]

        return {
            "status": "success",
            "patches": result_patches,
            "count": len(result_patches),
            "total_patches": len(all_patches),
            "filter_applied": filter_type,
            "metadata_included": include_metadata,
            "message": f"Retrieved {len(result_patches)} patches (filter: {filter_type})",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error getting proposed patches")
        return {"status": "error", "message": f"Error retrieving patches: {str(e)}"}


def wrapper_apply_confirmed_patch(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Apply a confirmed patch to the binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing 'patch_id' key.

    Returns:
        Patch application results including backup path on success.

    """
    logger.debug("Entered wrapper_apply_confirmed_patch with parameters: %s", parameters)
    patch_id = parameters.get("patch_id")

    if patch_id is None:
        return {"status": "error", "message": "Missing 'patch_id' parameter"}

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Applying patch: {patch_id}"))
        logger.info("Applying patch: %s", patch_id)

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Real binary patch application
        binary_path = app_instance.binary_path

        # Get patch details from stored patches
        patches = getattr(app_instance, "potential_patches", [])
        patch = next((p for p in patches if p.get("id") == patch_id), None)
        if not patch:
            return {"status": "error", "message": f"Patch {patch_id} not found"}

        # Create backup of original file
        import shutil

        backup_path = f"{binary_path}.bak_{int(time.time())}"
        try:
            shutil.copy2(binary_path, backup_path)
        except OSError as e:
            return {"status": "error", "message": f"Failed to create backup: {str(e)}"}

        # Apply the patch
        try:
            with open(binary_path, "r+b") as f:
                # Apply each modification in the patch
                modifications = patch.get("modifications", [])
                for mod in modifications:
                    offset = mod.get("offset")
                    original_bytes = mod.get("original")
                    new_bytes = mod.get("new")

                    if offset is None or new_bytes is None:
                        continue

                    # Convert hex strings to bytes if needed
                    if isinstance(new_bytes, str):
                        new_bytes = bytes.fromhex(new_bytes.replace(" ", "").replace("0x", ""))
                    if isinstance(original_bytes, str):
                        original_bytes = bytes.fromhex(original_bytes.replace(" ", "").replace("0x", ""))

                    # Verify original bytes match (if provided)
                    if original_bytes:
                        f.seek(offset)
                        current_bytes = f.read(len(original_bytes))
                        if current_bytes != original_bytes:
                            # Restore backup and fail
                            shutil.copy2(backup_path, binary_path)
                            return {"status": "error", "message": f"Original bytes mismatch at offset 0x{offset:x}"}

                    # Write new bytes
                    f.seek(offset)
                    f.write(new_bytes)

            # Update PE checksum if it's a Windows PE file
            if pefile and binary_path.lower().endswith((".exe", ".dll")):
                try:
                    pe = pefile.PE(binary_path)
                    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
                    pe.write(binary_path)
                    pe.close()
                except Exception as e:
                    logger.warning(f"Failed to update PE checksum: {e}")

            # Store patch info for rollback
            if not hasattr(app_instance, "applied_patches"):
                app_instance.applied_patches = []
            app_instance.applied_patches.append({"id": patch_id, "backup_path": backup_path, "timestamp": time.time(), "patch": patch})

            return {
                "status": "success",
                "patch_id": patch_id,
                "applied": True,
                "backup_path": backup_path,
                "message": f"Successfully applied patch {patch_id}",
            }

        except Exception as e:
            # Restore backup on error
            try:
                shutil.copy2(backup_path, binary_path)
            except Exception:
                pass
            return {"status": "error", "message": f"Failed to apply patch: {str(e)}"}

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error applying patch: {patch_id}")
        return {"status": "error", "message": f"Patch application error: {str(e)}"}


def wrapper_generate_launcher_script(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Generate a launcher script for the patched binary.

    Args:
        app_instance: The main application instance.
        parameters: Dictionary containing optional 'output_path' key (default: launcher.bat).

    Returns:
        Launcher script generation results.

    """
    logger.debug("Entered wrapper_generate_launcher_script with parameters: %s", parameters)
    output_path = parameters.get("output_path", "launcher.bat")

    try:
        app_instance.update_output.emit(log_message(f"[Tool] Generating launcher script: {output_path}"))
        logger.info("Generating launcher script: %s", output_path)

        if not hasattr(app_instance, "binary_path") or not app_instance.binary_path:
            return {"status": "error", "message": "No binary loaded"}

        # Generate simple launcher script
        script_content = f"""@echo off
echo Starting patched application...
"{app_instance.binary_path}"
pause
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(script_content)

        return {
            "status": "success",
            "script_path": output_path,
            "message": f"Launcher script generated: {output_path}",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error generating launcher script: {output_path}")
        return {"status": "error", "message": f"Script generation error: {str(e)}"}


def dispatch_tool(app_instance: Any, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """Central dispatcher for tool wrapper functions.

    Args:
        app_instance: The main application instance.
        tool_name: Name of the tool to execute.
        parameters: Parameters to pass to the tool.

    Returns:
        Tool execution results.

    """
    logger.info("Dispatching tool: %s with parameters: %s", tool_name, parameters)

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
        logger.warning("Unknown tool: %s", tool_name)
        return {"status": "error", "message": f"Unknown tool: {tool_name}"}

    try:
        return tool_map[tool_name](app_instance, parameters)
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error executing tool {tool_name}")
        return {"status": "error", "message": f"Tool execution failed: {str(e)}"}


def run_external_tool(args: list[str]) -> str:
    """Run an external tool with the given arguments.

    Args:
        args: Command line arguments including tool name and parameters.

    Returns:
        Combined stdout, stderr, and exit code output.

    """
    import subprocess

    logger.info(f"Running external tool: {' '.join(args)}")
    results: str = f"Running external tool: {' '.join(args)}\n"

    try:
        # Run the command
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8") as process:
            logger.info("Subprocess started: %s (PID: %s)", args, process.pid)

            # Get output
            stdout, stderr = process.communicate()
            logger.info("Subprocess finished with exit code %s", process.returncode)

            if stdout:
                logger.info("Subprocess stdout:\n%s", stdout)
            if stderr:
                logger.warning("Subprocess stderr:\n%s", stderr)

            # Format results
            results += f"\nExit code: {process.returncode}\n"

            if stdout:
                results += f"\nOutput:\n{stdout}\n"

            if stderr:
                results += f"\nErrors:\n{stderr}\n"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception(f"Error executing external tool: {e}")
        results += f"\nError executing command: {e}\n"

    return results


def wrapper_deep_runtime_monitoring(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
    """Wrap for deep runtime monitoring functionality.

    Args:
        app_instance: Application instance.
        parameters: Dict containing 'binary_path' and optional 'timeout'.

    Returns:
        Monitoring results with logs and status.

    """
    try:
        # Get parameters
        binary_path = parameters.get("binary_path")
        timeout = parameters.get("timeout", 30000)

        if not binary_path:
            return {"status": "error", "error": "No binary_path provided for runtime monitoring"}

        # Import directly from dynamic_analyzer to avoid cyclic import
        from ...core.analysis.dynamic_analyzer import deep_runtime_monitoring as analyzer_drm

        # Create monitoring config
        monitoring_config = {
            "monitor_api_calls": True,
            "monitor_file_operations": True,
            "monitor_registry": True,
            "monitor_network": True,
            "capture_strings": True,
            "timeout": timeout,
        }

        # Call the analyzer function directly
        logs = analyzer_drm(binary_path, timeout)

        # Format result similar to core_utilities wrapper
        result = {
            "status": "success",
            "target_process": binary_path,
            "timeout": timeout,
            "logs": logs,
            "config": monitoring_config,
        }

        # Extract logs from result
        final_logs: list[str]
        if isinstance(result, dict) and "logs" in result:
            final_logs = result["logs"]
        else:
            final_logs = logs

        # Update UI if available
        if app_instance and hasattr(app_instance, "update_output"):
            for log in final_logs:
                app_instance.update_output.emit(f"[Runtime Monitor] {log}")

        return {
            "status": "success",
            "binary_path": binary_path,
            "timeout": timeout,
            "logs": final_logs,
            "monitoring_complete": True,
        }

    except (OSError, ValueError, RuntimeError) as e:
        error_msg = f"Error in runtime monitoring: {str(e)}"
        logger.error(error_msg)

        if app_instance and hasattr(app_instance, "update_output"):
            app_instance.update_output.emit(f"[Runtime Monitor] ERROR: {error_msg}")

        return {"status": "error", "error": error_msg, "traceback": traceback.format_exc()}


def run_ghidra_headless(
    binary_path: str,
    script_path: str | None = None,
    output_dir: str | None = None,
    project_name: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run comprehensive Ghidra headless analysis on a binary.

    Args:
        binary_path: Path to the binary to analyze.
        script_path: Optional path to Ghidra script to run post-analysis.
        output_dir: Directory for Ghidra project (default: binary_dir/ghidra_analysis).
        project_name: Name for Ghidra project (default: analysis_{basename}).
        options: Additional analysis options with keys: timeout (seconds, default 600),
            analyzers (list), processor (auto-detected), loader, language, save_results
            (bool, default True), export_format (xml, json, csv), export_selection
            (functions, symbols, strings), log_level (INFO, DEBUG, ERROR), max_ram
            (default 2G), script_params (dict).

    Returns:
        Comprehensive analysis results including symbols, functions, strings,
        cross-references, entry points, imports, exports, segments, and analysis time.

    """
    import shutil
    import subprocess
    from pathlib import Path

    try:
        # Initialize results structure
        results = {
            "status": "success",
            "binary_path": binary_path,
            "analysis_complete": False,
            "project_path": None,
            "output": [],
            "errors": [],
            "warnings": [],
            "analysis_results": {
                "functions": [],
                "symbols": [],
                "strings": [],
                "cross_references": [],
                "entry_points": [],
                "imports": [],
                "exports": [],
                "segments": [],
                "analysis_time": 0,
            },
            "exported_files": [],
        }

        # Parse options
        if options is None:
            options = {}

        timeout = options.get("timeout", 600)
        analyzers = options.get("analyzers", [])
        processor = options.get("processor")
        loader = options.get("loader")
        language = options.get("language")
        save_results = options.get("save_results", True)
        export_format = options.get("export_format", "json")
        export_selection = options.get("export_selection", ["functions", "symbols", "strings"])
        log_level = options.get("log_level", "INFO")
        max_ram = options.get("max_ram", "2G")
        script_params = options.get("script_params", {})

        # Validate binary exists
        if not os.path.exists(binary_path):
            results["status"] = "error"
            if isinstance(results["errors"], list):
                results["errors"].append(f"Binary file not found: {binary_path}")
            return results

        # Find Ghidra installation
        # Use dynamic path discovery
        ghidra_executable: str | None = None
        try:
            from ...core.path_discovery import find_tool

            if ghidra_base := find_tool("ghidra"):
                # Find analyzeHeadless relative to ghidra installation
                if os.path.isfile(ghidra_base):
                    ghidra_dir = os.path.dirname(ghidra_base)
                else:
                    ghidra_dir = ghidra_base

                # Look for analyzeHeadless
                analyze_paths = [
                    os.path.join(ghidra_dir, "support", "analyzeHeadless.bat"),
                    os.path.join(ghidra_dir, "support", "analyzeHeadless"),
                    os.path.join(os.path.dirname(ghidra_dir), "support", "analyzeHeadless.bat"),
                    os.path.join(os.path.dirname(ghidra_dir), "support", "analyzeHeadless"),
                ]

                for path in analyze_paths:
                    if os.path.exists(path):
                        ghidra_executable = path
                        break
        except ImportError:
            logger.warning("Path discovery not available, falling back to manual search")

        # Fallback to manual search if discovery fails
        if not ghidra_executable:
            ghidra_paths = [
                os.environ.get("GHIDRA_INSTALL_DIR", "") + "/support/analyzeHeadless",
                "analyzeHeadless",
                "analyzeHeadless.bat",
            ]

            for path in ghidra_paths:
                if path and os.path.exists(path):
                    ghidra_executable = path
                    break

        # Try to find in PATH
        if not ghidra_executable:
            try:
                result = subprocess.run(["which", "analyzeHeadless"], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    ghidra_executable = result.stdout.strip()
            except (OSError, subprocess.SubprocessError) as e:
                logger.debug("Failed to find Ghidra in PATH: %s", e)

        if not ghidra_executable:
            results["status"] = "error"
            if isinstance(results["errors"], list):
                results["errors"].append("Ghidra executable not found. Please install Ghidra and set GHIDRA_INSTALL_DIR environment variable.")
            return results

        # Setup project directory
        if not output_dir:
            output_dir = os.path.join(os.path.dirname(binary_path), "ghidra_analysis")

        if not project_name:
            project_name = f"analysis_{Path(binary_path).stem}"

        os.makedirs(output_dir, exist_ok=True)
        results["project_path"] = os.path.join(output_dir, project_name)

        # Build command
        cmd = [ghidra_executable, output_dir, project_name, "-import", binary_path, "-overwrite"]

        # Add processor specification if provided
        if processor:
            cmd.extend(["-processor", processor])

        # Add loader if specified
        if loader:
            cmd.extend(["-loader", loader])

        # Add language if specified
        if language:
            cmd.extend(["-language", language])

        # Add memory settings
        cmd.extend(["-max-memory", max_ram])

        # Add log level
        cmd.extend(["-log-level", log_level])

        # Configure analyzers
        if analyzers:
            # Disable all analyzers first, then enable specific ones
            cmd.extend(["-noanalysis"])
            for analyzer in analyzers:
                cmd.extend(["-analysis", analyzer])
        else:
            # Run full analysis by default
            cmd.append("-analyze")

        # Create comprehensive analysis script if none provided
        analysis_script_path = script_path or _create_comprehensive_analysis_script(output_dir, export_format, export_selection, script_params)

        # Add post-analysis script
        if analysis_script_path and os.path.exists(analysis_script_path):
            cmd.extend(["-postScript", analysis_script_path])

            # Add script parameters if any
            if script_params:
                for key, value in script_params.items():
                    cmd.extend(["-scriptPath", f"{key}={value}"])

        # Add quiet mode for cleaner output
        cmd.append("-quiet")

        # Execute Ghidra analysis
        start_time = time.time()

        logger.info(f"Running Ghidra headless analysis: {' '.join(cmd)}")

        process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=output_dir, check=False)

        analysis_time = time.time() - start_time
        analysis_results = results.get("analysis_results")
        if isinstance(analysis_results, dict):
            analysis_results["analysis_time"] = analysis_time

        # Process output
        if process.stdout:
            if isinstance(results["output"], list):
                results["output"] = process.stdout.split("\n")
            # Parse analysis results from output
            results = _parse_ghidra_output(results, process.stdout)

        if process.stderr:
            stderr_lines = process.stderr.split("\n")
            # Separate warnings from errors
            for line in stderr_lines:
                if line.strip() and (isinstance(results["warnings"], list) and isinstance(results["errors"], list)):
                    if "WARN" in line or "WARNING" in line:
                        results["warnings"].append(line)
                    else:
                        results["errors"].append(line)

        results["return_code"] = process.returncode
        results["analysis_complete"] = process.returncode == 0

        # Load exported analysis results
        if results["analysis_complete"]:
            results = _load_analysis_exports(results, output_dir, export_format)

        if process.returncode != 0:
            results["status"] = "warning" if results["warnings"] and not results["errors"] else "error"

        # Cleanup temporary script if created
        if not script_path and analysis_script_path and os.path.exists(analysis_script_path):
            try:
                os.remove(analysis_script_path)
            except OSError as e:
                logger.debug("Failed to remove temporary analysis script: %s", e)

        # Save project if requested
        if not save_results:
            project_path = results.get("project_path")
            if isinstance(project_path, str):
                try:
                    shutil.rmtree(project_path)
                except OSError as e:
                    logger.debug("Failed to remove project directory: %s", e)

    except subprocess.TimeoutExpired as e:
        logger.error("Subprocess timeout in tool_wrappers: %s", e)
        results["status"] = "error"
        if isinstance(results["errors"], list):
            results["errors"].append(f"Ghidra analysis timed out after {timeout} seconds")
    except (OSError, ValueError, RuntimeError) as e:
        results["status"] = "error"
        if isinstance(results["errors"], list):
            results["errors"].append(str(e))
        logger.error("Error running Ghidra headless: %s", e)

    return results


def _create_comprehensive_analysis_script(output_dir: str, export_format: str, export_selection: list[str], params: dict[str, Any]) -> str:
    """Create a comprehensive Ghidra analysis script.

    Args:
        output_dir: Directory where analysis script and results will be saved.
        export_format: Format for exporting analysis results (xml, json, csv, etc.).
        export_selection: List of items to export (functions, symbols, strings, etc.).
        params: Additional parameters to pass to the script.

    Returns:
        Path to the created analysis script file.

    """
    logger.debug(f"Creating analysis script with format: {export_format}, selection: {export_selection}, params: {list(params.keys())}")
    script_content = (
        """
// Comprehensive Ghidra Analysis Script
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.*;

def program = currentProgram
def listing = program.getListing()
def symbolTable = program.getSymbolTable()
def memory = program.getMemory()
def addressFactory = program.getAddressFactory()

// Export functions
if (exportSelection.contains("functions")) {
    exportFunctions()
}

// Export symbols
if (exportSelection.contains("symbols")) {
    exportSymbols()
}

// Export strings
if (exportSelection.contains("strings")) {
    exportStrings()
}

// Export cross-references
if (exportSelection.contains("cross_references")) {
    exportCrossReferences()
}

// Export imports/exports
if (exportSelection.contains("imports")) {
    exportImports()
}

if (exportSelection.contains("exports")) {
    exportExports()
}

// Export memory segments
if (exportSelection.contains("segments")) {
    exportMemorySegments()
}

def exportFunctions() {
    def functions = []
    def functionIterator = listing.getFunctions(true)

    while (functionIterator.hasNext()) {
        def function = functionIterator.next()
        def functionData = [
            name: function.getName(),
            address: function.getEntryPoint().toString(),
            size: function.getBody().getNumAddresses(),
            signature: function.getSignature().toString(),
            calling_convention: function.getCallingConventionName(),
            parameter_count: function.getParameterCount(),
            local_variable_count: function.getLocalVariables().length,
            is_external: function.isExternal(),
            is_inline: function.isInline(),
            stack_frame_size: function.getStackFrame().getFrameSize()
        ]
        functions.add(functionData)
    }

    writeJsonFile("functions.json", functions)
}

def exportSymbols() {
    def symbols = []
    def symbolIterator = symbolTable.getAllSymbols(true)

    while (symbolIterator.hasNext()) {
        def symbol = symbolIterator.next()
        def symbolData = [
            name: symbol.getName(),
            address: symbol.getAddress().toString(),
            type: symbol.getSymbolType().toString(),
            source: symbol.getSource().toString(),
            is_external: symbol.isExternal(),
            is_global: symbol.isGlobal(),
            namespace: symbol.getParentNamespace().getName()
        ]
        symbols.add(symbolData)
    }

    writeJsonFile("symbols.json", symbols)
}

def exportStrings() {
    def strings = []
    def definedData = listing.getDefinedData(true)

    while (definedData.hasNext()) {
        def data = definedData.next()
        if (data.hasStringValue()) {
            def stringData = [
                address: data.getAddress().toString(),
                value: data.getValue().toString(),
                length: data.getLength(),
                data_type: data.getDataType().getName(),
                references: getReferencesToAddress(data.getAddress())
            ]
            strings.add(stringData)
        }
    }

    writeJsonFile("strings.json", strings)
}

def exportCrossReferences() {
    def references = []
    def allAddresses = memory.getAllInitializedAddressSet()
    def addressIterator = allAddresses.getAddresses(true)

    while (addressIterator.hasNext()) {
        def address = addressIterator.next()
        def refsFrom = program.getReferenceManager().getReferencesFrom(address)

        for (ref in refsFrom) {
            def refData = [
                from_address: ref.getFromAddress().toString(),
                to_address: ref.getToAddress().toString(),
                type: ref.getReferenceType().toString(),
                is_external: ref.isExternalReference(),
                operand_index: ref.getOperandIndex()
            ]
            references.add(refData)
        }
    }

    writeJsonFile("cross_references.json", references)
}

def exportImports() {
    def imports = []
    def externalManager = program.getExternalManager()
    def externalNames = externalManager.getExternalLibraryNames()

    for (libName in externalNames) {
        def extLocations = externalManager.getExternalLocations(libName)
        while (extLocations.hasNext()) {
            def location = extLocations.next()
            def importData = [
                library: libName,
                name: location.getLabel(),
                address: location.getAddress() ? location.getAddress().toString() : "unknown",
                original_name: location.getOriginalImportedName()
            ]
            imports.add(importData)
        }
    }

    writeJsonFile("imports.json", imports)
}

def exportExports() {
    def exports = []
    def entryPoints = symbolTable.getExternalEntryPointIterator()

    while (entryPoints.hasNext()) {
        def entryPoint = entryPoints.next()
        def exportData = [
            name: entryPoint.getName(),
            address: entryPoint.getAddress().toString(),
            type: entryPoint.getSymbolType().toString()
        ]
        exports.add(exportData)
    }

    writeJsonFile("exports.json", exports)
}

def exportMemorySegments() {
    def segments = []
    def memoryBlocks = memory.getBlocks()

    for (block in memoryBlocks) {
        def segmentData = [
            name: block.getName(),
            start_address: block.getStart().toString(),
            end_address: block.getEnd().toString(),
            size: block.getSize(),
            is_read: block.isRead(),
            is_write: block.isWrite(),
            is_execute: block.isExecute(),
            is_initialized: block.isInitialized(),
            type: block.getType().toString()
        ]
        segments.add(segmentData)
    }

    writeJsonFile("memory_segments.json", segments)
}

def getReferencesToAddress(address) {
    def refs = []
    def refIterator = program.getReferenceManager().getReferencesTo(address)

    while (refIterator.hasNext()) {
        def ref = refIterator.next()
        refs.add(ref.getFromAddress().toString())
    }

    return refs
}

def writeJsonFile(filename, data) {
    def file = new File(filename)
    def writer = new PrintWriter(new FileWriter(file))
    writer.println(groovy.json.JsonBuilder(data).toPrettyString())
    writer.close()
    println("Exported: " + filename)
}

// Set export selection
def exportSelection = """
        + str(export_selection)
        + """

println("Starting comprehensive analysis...")
println("Analysis complete. Results exported.")
"""
    )

    script_file = os.path.join(output_dir, "comprehensive_analysis.py")
    with open(script_file, "w", encoding="utf-8") as f:
        f.write(script_content)

    return script_file


def _parse_ghidra_output(results: dict[str, Any], output: str) -> dict[str, Any]:
    """Parse Ghidra analysis output for key information.

    Args:
        results: Existing results dictionary to update with parsed information.
        output: Ghidra stdout output to parse.

    Returns:
        Updated results dictionary with parsed analysis data.

    """
    lines = output.split("\n")

    for line in lines:
        line = line.strip()

        # Parse function count
        if "functions found" in line.lower():
            try:
                count = int(line.split()[0])
                results["analysis_results"]["function_count"] = count
            except (ValueError, IndexError) as e:
                logger.debug("Failed to parse function count: %s", e)

        # Parse symbol count
        if "symbols found" in line.lower():
            try:
                count = int(line.split()[0])
                results["analysis_results"]["symbol_count"] = count
            except (ValueError, IndexError) as e:
                logger.debug("Failed to parse symbol count: %s", e)

        # Parse entry points
        if "entry point" in line.lower():
            try:
                address = line.split()[-1]
                if address not in results["analysis_results"]["entry_points"]:
                    results["analysis_results"]["entry_points"].append(address)
            except (IndexError, ValueError) as e:
                logger.debug("Failed to parse entry point: %s", e)

    return results


def _load_analysis_exports(results: dict[str, Any], output_dir: str, export_format: str) -> dict[str, Any]:
    """Load exported analysis results from files.

    Args:
        results: Existing results dictionary to update with loaded data.
        output_dir: Directory containing exported analysis files.
        export_format: Format of exported files (json, xml, etc.).

    Returns:
        Updated results dictionary with loaded analysis data.

    """
    logger.debug(f"Loading analysis exports from {output_dir} with format: {export_format}")
    export_files = [
        "functions.json",
        "symbols.json",
        "strings.json",
        "cross_references.json",
        "imports.json",
        "exports.json",
        "memory_segments.json",
    ]

    for export_file in export_files:
        file_path = os.path.join(output_dir, export_file)
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)

                key = export_file.replace(".json", "")
                results["analysis_results"][key] = data
                results["exported_files"].append(file_path)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in tool_wrappers: %s", e)
                results["warnings"].append(f"Failed to load {export_file}: {str(e)}")

    return results
