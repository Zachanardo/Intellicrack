"""Ghidra Analysis Engine.

This module provides the core functionality for running Ghidra headless analysis
and processing the results.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import shutil
import subprocess
import tempfile
from threading import Thread

from intellicrack.config import get_config
from intellicrack.utils.subprocess_security import secure_popen


def _run_ghidra_thread(main_app, command, temp_dir):
    """Runs the Ghidra command in a background thread and cleans up afterward."""
    try:
        main_app.update_output.emit(f"[Ghidra] Running command: {' '.join(command)}")
        # Use secure subprocess wrapper with validation
        # This prevents command injection while maintaining functionality
        process = secure_popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore", shell=False, cwd=temp_dir
        )

        stdout, stderr = process.communicate()

        if process.returncode == 0:
            main_app.update_output.emit("[Ghidra] Analysis completed successfully.")
            # In a real implementation, you would parse Ghidra's output here.
        else:
            main_app.update_output.emit(f"[Ghidra] Analysis failed with return code {process.returncode}.")
            if stdout:
                main_app.update_output.emit(f"[Ghidra STDOUT]:\n{stdout}")
            if stderr:
                main_app.update_output.emit(f"[Ghidra STDERR]:\n{stderr}")

    except FileNotFoundError:
        main_app.update_output.emit("[Ghidra] Error: Command not found. Ensure Ghidra is in your system's PATH.")
    except Exception as e:
        main_app.update_output.emit(f"[Ghidra] An unexpected error occurred: {e}")
    finally:
        try:
            shutil.rmtree(temp_dir)
            main_app.update_output.emit(f"[Ghidra] Cleaned up temporary project directory: {temp_dir}")
        except Exception as e:
            main_app.update_output.emit(f"[Ghidra] Warning: Failed to clean up temporary directory {temp_dir}: {e}")

        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Ghidra Analysis")


def run_advanced_ghidra_analysis(main_app):
    """Launches a Ghidra headless analysis session."""
    if not main_app.current_binary:
        main_app.update_output.emit("[Ghidra] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary
    config = get_config()
    # The get_tool_path method should return the directory where Ghidra is installed.
    ghidra_install_dir = config.get_tool_path("ghidra")

    if not ghidra_install_dir or not os.path.isdir(ghidra_install_dir):
        main_app.update_output.emit(f"[Ghidra] Error: Ghidra installation directory not configured or invalid: {ghidra_install_dir}")
        return

    headless_script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headless_path = os.path.join(ghidra_install_dir, "support", headless_script_name)

    if not os.path.exists(headless_path):
        main_app.update_output.emit(f"[Ghidra] Error: Headless analyzer not found at {headless_path}")
        return

    temp_dir = tempfile.mkdtemp(prefix="intellicrack_ghidra_")
    project_name = "temp_project"

    # This default script performs a basic analysis. A real implementation would allow script selection.
    command = [
        headless_path,
        temp_dir,
        project_name,
        "-import",
        binary_path,
        "-postScript",
        "Ghidra_Function_Info.py",  # A common, useful default script
        "-deleteProject",
    ]

    thread = Thread(target=_run_ghidra_thread, args=(main_app, command, temp_dir), daemon=True)
    thread.start()
    main_app.update_output.emit("[Ghidra] Headless analysis task submitted.")
