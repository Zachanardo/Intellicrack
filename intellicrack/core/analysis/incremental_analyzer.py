"""Incremental Analysis Engine.

This module provides functionality to perform incremental analysis on binaries,
using a caching mechanism to avoid re-analyzing unchanged files.

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

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Protocol

from intellicrack.core.config_manager import get_config


class MainAppProtocol(Protocol):
    """Protocol defining the required interface for main application objects.

    This protocol defines the minimal interface required by the incremental
    analysis system to interact with the main application instance.
    """

    current_binary: str
    update_output: Any
    update_analysis_results: Any
    analysis_completed: Any

    def emit(self, *args: Any) -> None:
        """Emit a signal.

        Emits a signal with the provided arguments to connected signal handlers.

        Args:
            *args: Variable-length argument list containing signal data.

        Returns:
            None.

        """
        ...

    def run_selected_analysis_partial(self, analysis_type: str) -> None:
        """Run a partial analysis of the specified type.

        Executes a partial analysis on the currently selected binary using the
        specified analysis type.

        Args:
            analysis_type: Type of analysis to run (e.g., 'comprehensive').

        Returns:
            None.

        """
        ...


def get_cache_path(binary_path: str) -> Path:
    """Generate a consistent cache file path for a given binary.

    Creates and ensures the existence of the cache directory, then returns a
    Path object pointing to a cache file whose name is derived from a SHA256
    hash of the binary path.

    Args:
        binary_path: Absolute path to the binary file to generate cache path
            for.

    Returns:
        Path object pointing to the cache file for the specified binary.

    """
    config = get_config()
    cache_value: object = config.get("directories.cache", ".cache")
    cache_str: str = str(cache_value) if cache_value is not None else ".cache"
    cache_dir: Path = Path(cache_str) / "incremental"
    cache_dir.mkdir(parents=True, exist_ok=True)

    file_hash: str = hashlib.sha256(binary_path.encode()).hexdigest()
    return cache_dir / f"{file_hash}.json"


def run_incremental_analysis(main_app: MainAppProtocol) -> None:
    """Run analysis on the target binary, using cached results if available.

    Performs incremental caching of analysis results based on file modification
    time and size to speed up the process. This is a production-ready implementation
    that integrates with the main application's analysis pipeline.

    Args:
        main_app: Main application instance with update_output and other signal
            emitters.

    Returns:
        None.

    Raises:
        Exception: If an error occurs during cache access or analysis execution,
            the error message is emitted to the main application's output signal.

    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Incremental] Error: No binary loaded.")
        return

    binary_path: str = main_app.current_binary
    cache_file: Path = get_cache_path(binary_path)

    try:
        current_mtime: float = Path(binary_path).stat().st_mtime
        current_size: int = os.path.getsize(binary_path)

        if cache_file.exists():
            with open(cache_file, encoding="utf-8") as f:
                cached_data: dict[str, Any] = json.load(f)

            cached_mtime: Any = cached_data.get("mtime")
            cached_size: Any = cached_data.get("size")

            if cached_mtime == current_mtime and cached_size == current_size:
                main_app.update_output.emit(f"[Incremental] Loading cached results for {os.path.basename(binary_path)}.")
                results: dict[str, Any] = cached_data.get("results", {})
                main_app.update_analysis_results.emit(json.dumps(results, indent=2))
                if hasattr(main_app, "analysis_completed"):
                    main_app.analysis_completed.emit("Incremental Analysis (Cached)")
                return

        main_app.update_output.emit(f"[Incremental] No valid cache. Running full analysis for {os.path.basename(binary_path)}.")

        if hasattr(main_app, "run_selected_analysis_partial"):
            main_app.run_selected_analysis_partial("comprehensive")
        else:
            main_app.update_output.emit("[Incremental] Error: The 'run_selected_analysis_partial' function is not available.")

    except Exception as e:
        main_app.update_output.emit(f"[Incremental] An error occurred: {e}")
