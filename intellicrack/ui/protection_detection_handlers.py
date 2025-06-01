"""
Protection Detection Handlers for Intellicrack UI

This module contains all the handler functions for protection detection features
that are called from the main UI buttons.
"""

import logging
from typing import Optional
from PyQt5.QtWidgets import QTextEdit, QMessageBox

# Import protection detection functions
from ..utils.protection_detection import (
    detect_commercial_protections,
    detect_checksum_verification,
    detect_self_healing_code,
    scan_for_bytecode_protectors
)
from ..utils.process_utils import (
    detect_hardware_dongles,
    detect_tpm_protection
)
from ..core.protection_bypass.tpm_bypass import TPMProtectionBypass
from ..core.protection_bypass.vm_bypass import VirtualizationDetectionBypass as VMDetectionBypass
from ..core.protection_bypass.dongle_emulator import HardwareDongleEmulator
from ..core.analysis.core_analysis import decrypt_embedded_script

logger = logging.getLogger(__name__)


class ProtectionDetectionHandlers:
    """Mixin class providing protection detection handler methods for IntellicrackApp."""
    
    def run_commercial_protection_scan(self):
        """Handler for detecting commercial software protections."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Detecting commercial protections...")
            logger.info(f"Starting commercial protection detection for: {self.binary_path}")
            
            # Run the detection
            results = detect_commercial_protections(self.binary_path)
            
            # Format output
            output = "=== Commercial Protection Detection Results ===\n\n"
            
            if results.get("error"):
                output += f"Error: {results['error']}\n"
            else:
                if results.get("protections_found"):
                    output += f"Found {len(results['protections_found'])} commercial protections:\n\n"
                    for protection in results["protections_found"]:
                        confidence = results.get("confidence_scores", {}).get(protection, 0.0)
                        output += f"• {protection} (Confidence: {confidence:.1%})\n"
                    
                    output += "\nDetection Indicators:\n"
                    for indicator in results.get("indicators", []):
                        output += f"  - {indicator}\n"
                else:
                    output += "No commercial protections detected.\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Commercial protection scan complete")
            logger.info(f"Commercial protection scan complete: {len(results.get('protections_found', []))} found")
            
        except Exception as e:
            error_msg = f"Error during commercial protection scan: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_hardware_dongle_detection(self):
        """Handler for detecting hardware dongles."""
        try:
            self.update_status("Detecting hardware dongles...")
            logger.info("Starting hardware dongle detection")
            
            # Run the detection
            results = detect_hardware_dongles(self)
            
            # Format output
            output = "=== Hardware Dongle Detection Results ===\n\n"
            for result in results:
                output += f"{result}\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Hardware dongle detection complete")
            logger.info("Hardware dongle detection complete")
            
        except Exception as e:
            error_msg = f"Error during hardware dongle detection: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_tpm_detection(self):
        """Handler for detecting TPM protection."""
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
                if results['tpm_present']:
                    output += f"TPM Version: {results.get('tpm_version', 'Unknown')}\n"
                    output += f"TPM Enabled: {'Yes' if results['tpm_enabled'] else 'No'}\n"
                    output += f"TPM Owned: {'Yes' if results['tpm_owned'] else 'No'}\n"
                    
                    if results.get("detection_methods"):
                        output += "\nDetection Methods:\n"
                        for method in results["detection_methods"]:
                            output += f"  - {method}\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("TPM detection complete")
            logger.info(f"TPM detection complete: Present={results['tpm_present']}")
            
        except Exception as e:
            error_msg = f"Error during TPM detection: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_checksum_detection(self):
        """Handler for detecting checksum/integrity verification."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Detecting checksum/integrity verification...")
            logger.info(f"Starting checksum detection for: {self.binary_path}")
            
            # Run the detection
            results = detect_checksum_verification(self.binary_path)
            
            # Format output
            output = "=== Checksum/Integrity Verification Detection Results ===\n\n"
            
            if results.get("error"):
                output += f"Error: {results['error']}\n"
            else:
                if results["checksum_verification_detected"]:
                    output += "✓ Checksum/Integrity verification detected!\n\n"
                    
                    if results.get("algorithms_found"):
                        output += "Hash Algorithms Found:\n"
                        for algo in results["algorithms_found"]:
                            output += f"  • {algo}\n"
                    
                    if results.get("indicators"):
                        output += "\nDetection Indicators:\n"
                        for indicator in results["indicators"]:
                            output += f"  - {indicator}\n"
                else:
                    output += "No checksum/integrity verification detected.\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Checksum detection complete")
            logger.info(f"Checksum detection complete: Detected={results['checksum_verification_detected']}")
            
        except Exception as e:
            error_msg = f"Error during checksum detection: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_self_healing_detection(self):
        """Handler for detecting self-healing/self-modifying code."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Detecting self-healing code...")
            logger.info(f"Starting self-healing code detection for: {self.binary_path}")
            
            # Run the detection
            results = detect_self_healing_code(self.binary_path)
            
            # Format output
            output = "=== Self-Healing Code Detection Results ===\n\n"
            
            if results.get("error"):
                output += f"Error: {results['error']}\n"
            else:
                if results["self_healing_detected"]:
                    output += "✓ Self-healing/self-modifying code detected!\n\n"
                    
                    if results.get("techniques"):
                        output += "Techniques Found:\n"
                        for technique in results["techniques"]:
                            output += f"  • {technique}\n"
                    
                    if results.get("indicators"):
                        output += "\nAPI Indicators:\n"
                        for indicator in results["indicators"]:
                            output += f"  - {indicator}\n"
                else:
                    output += "No self-healing code detected.\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Self-healing code detection complete")
            logger.info(f"Self-healing code detection complete: Detected={results['self_healing_detected']}")
            
        except Exception as e:
            error_msg = f"Error during self-healing code detection: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_tpm_bypass(self):
        """Handler for TPM bypass functionality."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Attempting TPM bypass...")
            logger.info(f"Starting TPM bypass for: {self.binary_path}")
            
            # Create TPM bypass instance
            tpm_bypass = TPMProtectionBypass(self)
            
            # Run the bypass
            results = tpm_bypass.bypass_tpm_checks()
            
            # Format output
            output = "=== TPM Bypass Results ===\n\n"
            
            if results["success"]:
                output += "✓ TPM bypass successful!\n\n"
            else:
                output += "⚠ TPM bypass partially successful.\n\n"
            
            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for method in results["methods_applied"]:
                    output += f"  • {method}\n"
            
            if results.get("errors"):
                output += "\nErrors Encountered:\n"
                for error in results["errors"]:
                    output += f"  - {error}\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("TPM bypass attempt complete")
            logger.info(f"TPM bypass complete: Success={results['success']}")
            
        except Exception as e:
            error_msg = f"Error during TPM bypass: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_vm_bypass(self):
        """Handler for VM detection bypass functionality."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Attempting VM detection bypass...")
            logger.info(f"Starting VM detection bypass for: {self.binary_path}")
            
            # Create VM bypass instance
            vm_bypass = VMDetectionBypass(self)
            
            # Run the bypass
            results = vm_bypass.bypass_vm_detection()
            
            # Format output
            output = "=== VM Detection Bypass Results ===\n\n"
            
            if results["success"]:
                output += "✓ VM detection bypass successful!\n\n"
            else:
                output += "⚠ VM detection bypass partially successful.\n\n"
            
            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for method in results["methods_applied"]:
                    output += f"  • {method}\n"
            
            if results.get("errors"):
                output += "\nErrors Encountered:\n"
                for error in results["errors"]:
                    output += f"  - {error}\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("VM detection bypass attempt complete")
            logger.info(f"VM detection bypass complete: Success={results['success']}")
            
        except Exception as e:
            error_msg = f"Error during VM detection bypass: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_dongle_emulation(self):
        """Handler for hardware dongle emulation functionality."""
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
                output += "✓ Hardware dongle emulation activated!\n\n"
            else:
                output += "⚠ Hardware dongle emulation partially successful.\n\n"
            
            if results.get("emulated_dongles"):
                output += "Emulated Dongle Types:\n"
                for dongle in results["emulated_dongles"]:
                    output += f"  • {dongle}\n"
                output += "\n"
            
            if results.get("methods_applied"):
                output += "Methods Applied:\n"
                for method in results["methods_applied"]:
                    output += f"  • {method}\n"
                output += "\n"
            
            if results.get("errors"):
                output += "Errors Encountered:\n"
                for error in results["errors"]:
                    output += f"  - {error}\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Hardware dongle emulation complete")
            logger.info(f"Dongle emulation complete: Success={results['success']}")
            
        except Exception as e:
            error_msg = f"Error during hardware dongle emulation: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)
    
    def run_embedded_script_detection(self):
        """Handler for embedded/encrypted script detection."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please load a binary file first!")
            return
            
        try:
            self.update_status("Detecting embedded/encrypted scripts...")
            logger.info(f"Starting embedded script detection for: {self.binary_path}")
            
            # Run the detection
            results = decrypt_embedded_script(self.binary_path)
            
            # Format output
            output = "=== Embedded/Encrypted Script Detection Results ===\n\n"
            
            if results:
                for result in results:
                    output += f"{result}\n"
            else:
                output += "No results returned from script detection.\n"
            
            # Update the protection results text area
            if hasattr(self, 'protection_results'):
                self.protection_results.append(output)
            
            self.update_status("Embedded script detection complete")
            logger.info("Embedded script detection complete")
            
        except Exception as e:
            error_msg = f"Error during embedded script detection: {str(e)}"
            logger.error(error_msg)
            self.update_status(error_msg)
            QMessageBox.critical(self, "Error", error_msg)