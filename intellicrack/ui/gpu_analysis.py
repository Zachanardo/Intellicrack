"""GPU analysis for Intellicrack UI.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from pathlib import Path
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QProgressBar,
    Qt,
    QVBoxLayout,
)
from intellicrack.utils.log_message import log_error, log_info, log_warning


class GpuAnalysis:
    """GPU-accelerated binary analysis UI integration.

    This class provides a UI wrapper around Intellicrack's comprehensive
    GPU acceleration infrastructure, integrating with existing GPU
    acceleration, OpenCL handlers, and Intel Arc B580 optimization.
    """

    def __init__(self) -> None:
        """Initialize GPU analysis with existing infrastructure integration."""
        self.logger = logging.getLogger(__name__)
        self.gpu_available = False
        self.framework_info = {}
        self.device_info = {}

        # Initialize GPU infrastructure
        self._initialize_gpu_support()

        # UI state tracking
        self.progress_dialog = None
        self.current_analysis = None

    def _initialize_gpu_support(self) -> None:
        """Initialize GPU support using existing infrastructure."""
        try:
            # Try to initialize GPU acceleration using existing infrastructure
            from intellicrack.core.gpu_acceleration import GPUAccelerator
            from intellicrack.handlers.opencl_handler import HAS_OPENCL, OPENCL_AVAILABLE
            from intellicrack.utils.gpu_autoloader import detect_gpu_frameworks

            # Initialize accelerator
            self.accelerator = GPUAccelerator()
            self.gpu_available = self.accelerator.framework != "cpu"
            self.framework_info = {
                "framework": self.accelerator.framework,
                "opencl_available": OPENCL_AVAILABLE,
                "has_opencl": HAS_OPENCL,
            }
            self.device_info = self.accelerator.device_info

            # Detect available frameworks
            try:
                frameworks = detect_gpu_frameworks()
                self.framework_info.update(frameworks)
            except Exception as e:
                self.logger.debug(f"Framework detection failed: {e}")

            if self.gpu_available:
                log_info(f"GPU Analysis initialized with {self.accelerator.framework}", category="GPU", context=self.device_info)
            else:
                log_warning("GPU Analysis initialized in CPU fallback mode", category="GPU")

        except ImportError as e:
            self.logger.error(f"Failed to initialize GPU infrastructure: {e}")
            self.gpu_available = False
            self.framework_info = {"framework": "cpu", "error": str(e)}
            log_error("GPU infrastructure initialization failed", category="GPU", exception=e)

    def run_gpu_accelerated_analysis(self, app) -> None:
        """Run GPU-accelerated binary analysis with UI integration.

        Args:
            app: Main application instance with binary data and UI signals

        """
        try:
            log_info("Starting GPU-accelerated binary analysis", category="GPU")

            # Get binary data from application
            binary_data = self._get_binary_data(app)
            if not binary_data:
                log_error("No binary data available for GPU analysis", category="GPU")
                if hasattr(app, "update_output"):
                    app.update_output.emit("[ERROR] No binary loaded for GPU analysis")
                return

            # Show progress dialog
            self._show_progress_dialog(app)

            # Use existing GPU benchmark function for analysis
            from intellicrack.utils.gpu_benchmark import run_gpu_accelerated_analysis

            # Update progress
            if hasattr(app, "update_output"):
                framework = self.framework_info.get("framework", "cpu")
                app.update_output.emit(f"[GPU] Initializing {framework} acceleration...")

            # Run analysis using existing infrastructure
            results = run_gpu_accelerated_analysis(app, binary_data)

            # Process and display results
            self._process_analysis_results(app, results)

            log_info(
                "GPU-accelerated analysis completed successfully",
                category="GPU",
                context={"framework": results.get("framework_used", "unknown")},
            )

        except Exception as e:
            self.logger.error(f"GPU analysis failed: {e}")
            log_error("GPU-accelerated analysis failed", category="GPU", exception=e)

            if hasattr(app, "update_output"):
                app.update_output.emit(f"[ERROR] GPU analysis failed: {e}")

        finally:
            self._hide_progress_dialog()

    def _get_binary_data(self, app) -> bytes | None:
        """Extract binary data from application state."""
        try:
            # Check various possible locations for binary data
            if hasattr(app, "binary_data") and app.binary_data:
                return app.binary_data

            # Try to get from current file
            if hasattr(app, "current_file") and app.current_file:
                file_path = Path(app.current_file)
                if file_path.exists() and file_path.is_file():
                    return file_path.read_bytes()

            # Try to get from loaded binary path
            if hasattr(app, "loaded_binary_path") and app.loaded_binary_path:
                file_path = Path(app.loaded_binary_path)
                if file_path.exists() and file_path.is_file():
                    return file_path.read_bytes()

            # Check if there's a selected file in file browser
            if hasattr(app, "file_browser") and hasattr(app.file_browser, "selected_file"):
                if app.file_browser.selected_file:
                    file_path = Path(app.file_browser.selected_file)
                    if file_path.exists() and file_path.is_file():
                        return file_path.read_bytes()

            return None

        except Exception as e:
            self.logger.error(f"Failed to get binary data: {e}")
            return None

    def _show_progress_dialog(self, app) -> None:
        """Show progress dialog for GPU analysis."""
        try:
            if not hasattr(app, "centralWidget") or not app.centralWidget():
                return

            self.progress_dialog = QDialog(app.centralWidget())
            self.progress_dialog.setWindowTitle("GPU Analysis")
            self.progress_dialog.setWindowFlags(Qt.WindowType.Tool)
            self.progress_dialog.setModal(True)
            self.progress_dialog.resize(400, 200)

            layout = QVBoxLayout(self.progress_dialog)

            # Info group
            info_group = QGroupBox("GPU Information")
            info_layout = QGridLayout(info_group)

            framework = self.framework_info.get("framework", "cpu")
            info_layout.addWidget(QLabel("Framework:"), 0, 0)
            info_layout.addWidget(QLabel(framework), 0, 1)

            if self.device_info:
                device_name = self.device_info.get("name", "Unknown")
                info_layout.addWidget(QLabel("Device:"), 1, 0)
                info_layout.addWidget(QLabel(device_name), 1, 1)

            layout.addWidget(info_group)

            # Progress group
            progress_group = QGroupBox("Analysis Progress")
            progress_layout = QVBoxLayout(progress_group)

            self.progress_bar = QProgressBar()
            self.progress_bar.setRange(0, 0)  # Indeterminate
            progress_layout.addWidget(self.progress_bar)

            self.status_label = QLabel("Initializing GPU analysis...")
            progress_layout.addWidget(self.status_label)

            layout.addWidget(progress_group)

            # Show dialog
            self.progress_dialog.show()

        except Exception as e:
            self.logger.error(f"Failed to show progress dialog: {e}")

    def _hide_progress_dialog(self) -> None:
        """Hide progress dialog."""
        try:
            if self.progress_dialog:
                self.progress_dialog.close()
                self.progress_dialog = None
        except Exception as e:
            self.logger.error(f"Failed to hide progress dialog: {e}")

    def _process_analysis_results(self, app, results: dict[str, Any]) -> None:
        """Process and display GPU analysis results."""
        try:
            if not results:
                return

            # Update progress dialog status
            if hasattr(self, "status_label") and self.status_label:
                self.status_label.setText("Processing results...")

            # Display results summary
            if hasattr(app, "update_output"):
                framework = results.get("framework_used", "cpu")
                gpu_available = results.get("gpu_available", False)

                app.update_output.emit(f"[GPU] Analysis completed using {framework}")
                app.update_output.emit(f"[GPU] GPU acceleration: {'enabled' if gpu_available else 'disabled'}")

                # Display analysis results
                analyses = results.get("analyses", {})

                # Pattern search results
                if "pattern_search" in analyses:
                    pattern_results = analyses["pattern_search"]
                    total_patterns = len(pattern_results)
                    total_matches = sum(r.get("match_count", 0) for r in pattern_results)
                    app.update_output.emit(f"[GPU] Pattern search: {total_matches} matches across {total_patterns} patterns")

                # Entropy analysis results
                if "entropy" in analyses:
                    entropy_data = analyses["entropy"]
                    avg_entropy = entropy_data.get("average_entropy", 0.0)
                    app.update_output.emit(f"[GPU] Entropy analysis: average {avg_entropy:.2f}")

                # High entropy sections
                if "high_entropy_sections" in analyses:
                    high_entropy = analyses["high_entropy_sections"]
                    if high_entropy:
                        count = len(high_entropy)
                        app.update_output.emit(f"[GPU] Found {count} high-entropy sections (potentially encrypted/packed)")

                # Device info
                if "device_info" in results and results["device_info"]:
                    device_info = results["device_info"]
                    device_name = device_info.get("name", "Unknown")
                    app.update_output.emit(f"[GPU] Device: {device_name}")

            # Store results for further processing
            self.current_analysis = results

        except Exception as e:
            self.logger.error(f"Failed to process analysis results: {e}")
            if hasattr(app, "update_output"):
                app.update_output.emit(f"[ERROR] Failed to process GPU analysis results: {e}")

    def get_gpu_status(self) -> dict[str, Any]:
        """Get current GPU status and capabilities.

        Returns:
            Dictionary containing GPU status information

        """
        return {
            "gpu_available": self.gpu_available,
            "framework_info": self.framework_info,
            "device_info": self.device_info,
            "current_analysis": self.current_analysis is not None,
        }

    def get_supported_formats(self) -> list[str]:
        """Get list of binary formats supported for GPU analysis.

        Returns:
            List of supported file extensions/formats

        """
        return [
            ".exe",
            ".dll",
            ".sys",  # Windows PE
            ".elf",
            ".so",  # Linux ELF
            ".dylib",  # macOS
            ".bin",
            ".img",  # Raw binary
            ".hex",  # Intel HEX
        ]

    def cleanup(self) -> None:
        """Cleanup GPU analysis resources."""
        try:
            self._hide_progress_dialog()
            self.current_analysis = None

            log_info("GPU Analysis cleanup completed", category="GPU")

        except Exception as e:
            self.logger.error(f"GPU analysis cleanup failed: {e}")
