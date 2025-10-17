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

from intellicrack.config import get_config


def get_cache_path(binary_path: str) -> Path:
    """Generate a consistent cache file path for a given binary."""
    config = get_config()
    # Use a dedicated subdirectory for incremental analysis cache
    cache_dir = Path(config.get("directories.cache", ".cache")) / "incremental"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Hash the absolute path to create a unique, filesystem-safe cache key
    file_hash = hashlib.sha256(binary_path.encode()).hexdigest()
    return cache_dir / f"{file_hash}.json"


def run_incremental_analysis(main_app):
    """Run analysis on the target binary, using cached results if available.

    to speed up the process. This is a production-ready implementation.
    """
    if not main_app.current_binary:
        main_app.update_output.emit("[Incremental] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary
    cache_file = get_cache_path(binary_path)

    try:
        # Use file modification time and size as the cache validation strategy.
        # For full integrity, a file hash would be better but slower.
        current_mtime = os.path.getmtime(binary_path)
        current_size = os.path.getsize(binary_path)

        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)

            if cached_data.get("mtime") == current_mtime and cached_data.get("size") == current_size:
                main_app.update_output.emit(f"[Incremental] Loading cached results for {os.path.basename(binary_path)}.")
                results = cached_data.get("results", {})
                main_app.update_analysis_results.emit(json.dumps(results, indent=2))
                if hasattr(main_app, "analysis_completed"):
                    main_app.analysis_completed.emit("Incremental Analysis (Cached)")
                return

        main_app.update_output.emit(f"[Incremental] No valid cache. Running full analysis for {os.path.basename(binary_path)}.")

        # If no valid cache, run a new comprehensive analysis.
        # This function is assumed to be on the main_app instance and to be blocking or threaded.
        if hasattr(main_app, "run_selected_analysis_partial"):
            # This will trigger the analysis and the results will be handled by the app's signal/slot mechanism.
            # We don't get the results back directly here.
            main_app.run_selected_analysis_partial("comprehensive")
            # The caching of the *new* result should be handled by the analysis completion signal handler.
        else:
            main_app.update_output.emit("[Incremental] Error: The 'run_selected_analysis_partial' function is not available.")

    except Exception as e:
        main_app.update_output.emit(f"[Incremental] An error occurred: {e}")
    finally:
        # The completion signal is emitted by the called analysis function.
        pass
