"""Protection Detection Handlers for Intellicrack UI.

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

import logging

from intellicrack.handlers.pyqt6_handler import QMessageBox

from ..core.analysis.core_analysis import decrypt_embedded_script
from ..core.protection_bypass.dongle_emulator import HardwareDongleEmulator
from ..core.protection_bypass.tpm_bypass import TPMProtectionBypass
from ..core.protection_bypass.vm_bypass import VirtualizationDetectionBypass as VMDetectionBypass

# Import protection detection functions
from ..protection.protection_detector import (
    detect_checksum_verification,
    detect_commercial_protections,
    detect_self_healing_code,
)
from ..utils.system.process_utils import detect_hardware_dongles, detect_tpm_protection

logger = logging.getLogger(__name__)


class ProtectionDetectionHandlers:
    """Mixin class providing protection detection handler methods for IntellicrackApp."""

    def __init__(self) -> None:
        """Initialize protection detection handlers."""
        self.binary_path = None

    def update_status(self, message: str) -> None:
        """Update status - should be overridden by parent class.

        Args:
            message: Status message to log and update.

        """
        logger.info(message)

    def run_commercial_protection_scan(self) -> None:
        """Handle detecting commercial software protections."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Detecting commercial protections...")
            logger.info("Starting commercial protection detection for: %s", self.binary_path)

            # Run the detection
            results = detect_commercial_protections(self.binary_path)

            # Format output
            output = "=== Commercial Protection Detection Results ===\n\n"

            if results.get("error"):
                output += f"Error: {results['error']}\n"
            elif results.get("protections_found"):
                output += f"Found {len(results['protections_found'])} commercial protections:\n\n"
                for _protection in results["protections_found"]:
                    confidence = results.get("confidence_scores", {}).get(_protection, 0.0)
                    output += f" {_protection} (Confidence: {confidence:.1%})\n"

                output += "\nDetection Indicators:\n"
                for _indicator in results.get("indicators", []):
                    output += f"  - {_indicator}\n"
            else:
                output += "No commercial protections detected.\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Commercial protection scan complete")
            logger.info(f"Commercial protection scan complete: {len(results.get('protections_found', []))} found")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during commercial protection scan: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_hardware_dongle_detection(self) -> None:
        """Handle detecting hardware dongles."""
        try:
            self.update_status("Detecting hardware dongles...")
            logger.info("Starting hardware dongle detection")

            # Run the detection
            results = detect_hardware_dongles()

            # Format output
            output = "=== Hardware Dongle Detection Results ===\n\n"
            for _result in results:
                output += f"{_result}\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Hardware dongle detection complete")
            logger.info("Hardware dongle detection complete")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during hardware dongle detection: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_tpm_detection(self) -> None:
        """Handle detecting TPM protection."""
        try:
            self.update_status("Detecting TPM protection...")
            logger.info("Starting TPM detection")

            # Run the detection
            results = detect_tpm_protection()

            # Format output
            output = "=== TPM Protection Detection Results ===\n\n"

            if results.get("error"):
                output += f"Error: {results['error']}\n"
            else:
                output += f"TPM Present: {'Yes' if results['tpm_present'] else 'No'}\n"
                if results["tpm_present"]:
                    output += f"TPM Version: {results.get('tpm_version', 'Unknown')}\n"
                    output += f"TPM Enabled: {'Yes' if results['tpm_enabled'] else 'No'}\n"
                    output += f"TPM Owned: {'Yes' if results['tpm_owned'] else 'No'}\n"

                    if results.get("detection_methods"):
                        output += "\nDetection Methods:\n"
                        for _method in results["detection_methods"]:
                            output += f"  - {_method}\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("TPM detection complete")
            logger.info(f"TPM detection complete: Present={results['tpm_present']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during TPM detection: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_checksum_detection(self) -> None:
        """Handle detecting checksum/integrity verification."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Detecting checksum/integrity verification...")
            logger.info("Starting checksum detection for: %s", self.binary_path)

            # Run the detection
            results = detect_checksum_verification(self.binary_path)

            # Format output
            output = "=== Checksum/Integrity Verification Detection Results ===\n\n"

            if results.get("error"):
                output += f"Error: {results['error']}\n"
            elif results["checksum_verification_detected"]:
                output += "OK Checksum/Integrity verification detected!\n\n"

                if results.get("algorithms_found"):
                    output += "Hash Algorithms Found:\n"
                    for _algo in results["algorithms_found"]:
                        output += f"   {_algo}\n"

                if results.get("indicators"):
                    output += "\nDetection Indicators:\n"
                    for _indicator in results["indicators"]:
                        output += f"  - {_indicator}\n"
            else:
                output += "No checksum/integrity verification detected.\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Checksum detection complete")
            logger.info(f"Checksum detection complete: Detected={results['checksum_verification_detected']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during checksum detection: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_self_healing_detection(self) -> None:
        """Handle detecting self-healing/self-modifying code."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Detecting self-healing code...")
            logger.info("Starting self-healing code detection for: %s", self.binary_path)

            # Run the detection
            results = detect_self_healing_code(self.binary_path)

            # Format output
            output = "=== Self-Healing Code Detection Results ===\n\n"

            if results.get("error"):
                output += f"Error: {results['error']}\n"
            elif results["self_healing_detected"]:
                output += "OK Self-healing/self-modifying code detected!\n\n"

                if results.get("techniques"):
                    output += "Techniques Found:\n"
                    for _technique in results["techniques"]:
                        output += f"   {_technique}\n"

                if results.get("indicators"):
                    output += "\nAPI Indicators:\n"
                    for _indicator in results["indicators"]:
                        output += f"  - {_indicator}\n"
            else:
                output += "No self-healing code detected.\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Self-healing code detection complete")
            logger.info(f"Self-healing code detection complete: Detected={results['self_healing_detected']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during self-healing code detection: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_tpm_bypass(self) -> None:
        """Handle TPM bypass functionality."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Attempting TPM bypass...")
            logger.info("Starting TPM bypass for: %s", self.binary_path)

            # Create TPM bypass instance
            tpm_bypass = TPMProtectionBypass(self)

            # Run the bypass
            results = tpm_bypass.bypass_tpm_checks()

            # Format output
            output = "=== TPM Bypass Results ===\n\n"

            if results["success"]:
                output += "OK TPM bypass successful!\n\n"
            else:
                output += "WARNING TPM bypass partially successful.\n\n"

            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for _method in results["methods_applied"]:
                    output += f"   {_method}\n"

            if results.get("errors"):
                output += "\nErrors Encountered:\n"
                for _error in results["errors"]:
                    output += f"  - {_error}\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("TPM bypass attempt complete")
            logger.info(f"TPM bypass complete: Success={results['success']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during TPM bypass: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_vm_bypass(self) -> None:
        """Handle VM detection bypass functionality."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Attempting VM detection bypass...")
            logger.info("Starting VM detection bypass for: %s", self.binary_path)

            # Create VM bypass instance
            vm_bypass = VMDetectionBypass(self)

            # Run the bypass
            results = vm_bypass.bypass_vm_detection()

            # Format output
            output = "=== VM Detection Bypass Results ===\n\n"

            if results["success"]:
                output += "OK VM detection bypass successful!\n\n"
            else:
                output += "WARNING VM detection bypass partially successful.\n\n"

            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for _method in results["methods_applied"]:
                    output += f"   {_method}\n"

            if results.get("errors"):
                output += "\nErrors Encountered:\n"
                for _error in results["errors"]:
                    output += f"  - {_error}\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("VM detection bypass attempt complete")
            logger.info(f"VM detection bypass complete: Success={results['success']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during VM detection bypass: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_dongle_emulation(self) -> None:
        """Handle hardware dongle emulation functionality."""
        try:
            self.update_status("Activating hardware dongle emulation...")
            logger.info("Starting hardware dongle emulation")

            # Create dongle emulator instance
            dongle_emulator = HardwareDongleEmulator(self)

            # Run the emulation (emulate all supported types by default)
            results = dongle_emulator.activate_dongle_emulation()

            # Format output
            output = "=== Hardware Dongle Emulation Results ===\n\n"

            if results["success"]:
                output += "OK Hardware dongle emulation activated!\n\n"
            else:
                output += "WARNING Hardware dongle emulation partially successful.\n\n"

            if results.get("emulated_dongles"):
                output += "Emulated Dongle Types:\n"
                for _dongle in results["emulated_dongles"]:
                    output += f"   {_dongle}\n"
                output += "\n"

            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for _method in results["methods_applied"]:
                    output += f"   {_method}\n"
                output += "\n"

            if results.get("errors"):
                output += "Errors Encountered:\n"
                for _error in results["errors"]:
                    output += f"  - {_error}\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Hardware dongle emulation complete")
            logger.info(f"Dongle emulation complete: Success={results['success']}")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during hardware dongle emulation: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)

    def run_embedded_script_detection(self) -> None:
        """Handle embedded/encrypted script detection."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return

        try:
            self.update_status("Detecting embedded/encrypted scripts...")
            logger.info("Starting embedded script detection for: %s", self.binary_path)

            # Run the detection
            results = decrypt_embedded_script(self.binary_path)

            # Format output
            output = "=== Embedded/Encrypted Script Detection Results ===\n\n"

            if results:
                for _result in results:
                    output += f"{_result}\n"
            else:
                output += "No results returned from script detection.\n"

            # Update the protection results text area
            if hasattr(self, "protection_results"):
                self.protection_results.append(output)

            self.update_status("Embedded script detection complete")
            logger.info("Embedded script detection complete")

        except (OSError, ValueError, RuntimeError) as e:
            error_msg = f"Error during embedded script detection: {e!s}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
