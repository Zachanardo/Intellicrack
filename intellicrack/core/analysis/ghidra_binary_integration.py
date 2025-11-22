"""Ghidra Binary Analysis Integration.

Provides seamless integration between Intellicrack's binary analyzer and Ghidra scripts
for advanced binary analysis, license validation detection, and protection bypass.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import logging
from pathlib import Path
from typing import Any

from .ghidra_script_runner import GhidraScriptRunner


logger = logging.getLogger(__name__)


class GhidraBinaryIntegration:
    """Integration layer between binary analyzer and Ghidra scripts."""

    def __init__(self, ghidra_path: Path) -> None:
        """Initialize Ghidra integration.

        Args:
            ghidra_path: Path to Ghidra installation directory

        """
        self.ghidra_path = ghidra_path
        self.script_runner = GhidraScriptRunner(ghidra_path)
        self.logger = logger

    def analyze_license_validation(
        self,
        binary_path: Path,
        deep_analysis: bool = True,
    ) -> dict[str, Any]:
        """Analyze license validation routines in binary.

        Args:
            binary_path: Path to binary to analyze
            deep_analysis: Perform comprehensive analysis if True

        Returns:
            Dictionary with license validation analysis results

        """
        try:
            script_name = "enhanced_licensing_analysis" if deep_analysis else "licensing_analysis"

            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name=script_name,
                parameters={},
            )

            self.logger.info(
                f"License validation analysis completed for {binary_path.name}: "
                f"{result.get('validation_functions', 0)} functions found",
            )

            return result

        except Exception as e:
            self.logger.error(f"License validation analysis failed: {e}")
            return {"error": str(e), "success": False}

    def detect_protections(self, binary_path: Path) -> dict[str, Any]:
        """Detect protection schemes and packers.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with detected protections

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="modern_packer_detector",
                parameters={},
            )

            protections_found = []
            if result.get("themida_detected"):
                protections_found.append("Themida")
            if result.get("vmprotect_detected"):
                protections_found.append("VMProtect")
            if result.get("enigma_detected"):
                protections_found.append("Enigma")

            self.logger.info(
                f"Protection detection completed for {binary_path.name}: "
                f"{len(protections_found)} protections found",
            )

            return {
                "protections": protections_found,
                "details": result,
                "success": True,
            }

        except Exception as e:
            self.logger.error(f"Protection detection failed: {e}")
            return {"error": str(e), "success": False, "protections": []}

    def analyze_crypto_routines(self, binary_path: Path) -> dict[str, Any]:
        """Analyze cryptographic routines and algorithms.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with crypto analysis results

        """
        try:
            signature_result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="crypto_signature_finder",
                parameters={},
            )

            identifier_result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="crypto_routine_identifier",
                parameters={},
            )

            algorithms_found = signature_result.get("algorithms", [])
            custom_crypto = identifier_result.get("custom_crypto", [])

            self.logger.info(
                f"Crypto analysis completed for {binary_path.name}: "
                f"{len(algorithms_found)} algorithms, {len(custom_crypto)} custom routines",
            )

            return {
                "standard_algorithms": algorithms_found,
                "custom_crypto": custom_crypto,
                "signature_details": signature_result,
                "identifier_details": identifier_result,
                "success": True,
            }

        except Exception as e:
            self.logger.error(f"Crypto analysis failed: {e}")
            return {"error": str(e), "success": False}

    def generate_keygen_template(self, binary_path: Path) -> dict[str, Any]:
        """Generate keygen template from license validation algorithm.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with keygen template and algorithm details

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="keygen_template_generator",
                parameters={},
            )

            self.logger.info(
                f"Keygen template generated for {binary_path.name}: "
                f"algorithm={result.get('algorithm_type', 'unknown')}",
            )

            return result

        except Exception as e:
            self.logger.error(f"Keygen template generation failed: {e}")
            return {"error": str(e), "success": False}

    def deobfuscate_control_flow(self, binary_path: Path) -> dict[str, Any]:
        """Deobfuscate control flow and remove junk code.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with deobfuscation results

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="control_flow_deobfuscator",
                parameters={},
            )

            self.logger.info(
                f"Control flow deobfuscation completed for {binary_path.name}: "
                f"{result.get('blocks_deobfuscated', 0)} blocks processed",
            )

            return result

        except Exception as e:
            self.logger.error(f"Control flow deobfuscation failed: {e}")
            return {"error": str(e), "success": False}

    def decrypt_strings(self, binary_path: Path) -> dict[str, Any]:
        """Automatically decrypt obfuscated strings.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with decrypted strings

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="string_decryption_automator",
                parameters={},
            )

            decrypted_count = len(result.get("decrypted_strings", []))

            self.logger.info(
                f"String decryption completed for {binary_path.name}: "
                f"{decrypted_count} strings decrypted",
            )

            return result

        except Exception as e:
            self.logger.error(f"String decryption failed: {e}")
            return {"error": str(e), "success": False}

    def detect_anti_analysis(self, binary_path: Path) -> dict[str, Any]:
        """Detect anti-analysis techniques.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with detected anti-analysis techniques

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="anti_analysis_detector",
                parameters={},
            )

            techniques = []
            if result.get("anti_debug"):
                techniques.append("anti-debug")
            if result.get("anti_vm"):
                techniques.append("anti-vm")
            if result.get("anti_dump"):
                techniques.append("anti-dump")

            self.logger.info(
                f"Anti-analysis detection completed for {binary_path.name}: "
                f"{len(techniques)} techniques found",
            )

            return {
                "techniques": techniques,
                "details": result,
                "success": True,
            }

        except Exception as e:
            self.logger.error(f"Anti-analysis detection failed: {e}")
            return {"error": str(e), "success": False, "techniques": []}

    def perform_comprehensive_analysis(
        self,
        binary_path: Path,
        include_decompilation: bool = False,
    ) -> dict[str, Any]:
        """Perform comprehensive binary analysis using multiple Ghidra scripts.

        Args:
            binary_path: Path to binary to analyze
            include_decompilation: Include full decompilation if True

        Returns:
            Dictionary with comprehensive analysis results

        """
        try:
            script_name = "advanced_analysis" if include_decompilation else "function_lister"

            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name=script_name,
                parameters={},
            )

            self.logger.info(
                f"Comprehensive analysis completed for {binary_path.name}: "
                f"{result.get('function_count', 0)} functions analyzed",
            )

            return result

        except Exception as e:
            self.logger.error(f"Comprehensive analysis failed: {e}")
            return {"error": str(e), "success": False}

    def unpack_binary(self, binary_path: Path, max_iterations: int = 10) -> dict[str, Any]:
        """Automatically unpack packed binary.

        Args:
            binary_path: Path to packed binary
            max_iterations: Maximum unpacking iterations

        Returns:
            Dictionary with unpacking results

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="automated_unpacker",
                parameters={"max_iterations": max_iterations},
            )

            self.logger.info(
                f"Unpacking completed for {binary_path.name}: OEP={hex(result.get('oep', 0))}",
            )

            return result

        except Exception as e:
            self.logger.error(f"Unpacking failed: {e}")
            return {"error": str(e), "success": False}

    def analyze_network_communication(self, binary_path: Path) -> dict[str, Any]:
        """Analyze network communication routines.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Dictionary with network analysis results

        """
        try:
            result = self.script_runner.run_script(
                binary_path=binary_path,
                script_name="network_analysis",
                parameters={},
            )

            self.logger.info(
                f"Network analysis completed for {binary_path.name}: "
                f"{len(result.get('network_functions', []))} functions found",
            )

            return result

        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return {"error": str(e), "success": False}

    def perform_licensing_crack_workflow(self, binary_path: Path) -> dict[str, Any]:
        """Complete workflow for analyzing and cracking licensing protection.

        Combines multiple analysis steps:
        1. Detect protections and packers
        2. Unpack if necessary
        3. Analyze license validation
        4. Detect crypto algorithms
        5. Generate keygen template
        6. Decrypt obfuscated strings
        7. Detect anti-analysis techniques

        Args:
            binary_path: Path to binary to crack

        Returns:
            Dictionary with complete workflow results

        """
        self.logger.info(f"Starting licensing crack workflow for {binary_path.name}")

        workflow_results = {
            "binary": str(binary_path),
            "success": True,
            "stages": {},
        }

        workflow_results["stages"]["protection_detection"] = self.detect_protections(binary_path)

        if any(
            prot in workflow_results["stages"]["protection_detection"].get("protections", [])
            for prot in ["VMProtect", "Themida", "Enigma"]
        ):
            self.logger.info("Packer detected, attempting to unpack...")
            workflow_results["stages"]["unpacking"] = self.unpack_binary(binary_path)

        workflow_results["stages"]["license_analysis"] = self.analyze_license_validation(
            binary_path, deep_analysis=True
        )

        workflow_results["stages"]["crypto_analysis"] = self.analyze_crypto_routines(binary_path)

        workflow_results["stages"]["keygen_generation"] = self.generate_keygen_template(binary_path)

        workflow_results["stages"]["string_decryption"] = self.decrypt_strings(binary_path)

        workflow_results["stages"]["anti_analysis"] = self.detect_anti_analysis(binary_path)

        self.logger.info(f"Licensing crack workflow completed for {binary_path.name}")

        return workflow_results

    def get_available_scripts(self) -> list[dict[str, Any]]:
        """Get list of dynamically discovered Ghidra scripts.

        Returns:
            List of dictionaries with script information

        """
        return self.script_runner.list_available_scripts()

    def get_script_info(self, script_name: str) -> dict[str, Any] | None:
        """Get information about a specific dynamically discovered script.

        Args:
            script_name: Name of script

        Returns:
            Dictionary with script information or None

        """
        if script := self.script_runner._get_script(script_name):
            return {
                "name": script.name,
                "description": script.description,
                "language": script.language,
                "timeout": script.timeout,
                "output_format": script.output_format,
                "parameters": script.parameters,
                "path": str(script.path),
            }
        return None

    def refresh_scripts(self) -> int:
        """Refresh the list of discovered scripts from filesystem.

        Returns:
            Number of scripts discovered

        """
        return self.script_runner.refresh_scripts()
