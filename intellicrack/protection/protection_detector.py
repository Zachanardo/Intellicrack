"""Run Protection Detection Module.

This module serves as the primary interface for protection detection in Intellicrack.
It uses the unified protection engine which provides comprehensive protection detection
through multiple analysis methods.

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

import hashlib
import logging
import os
import sys
from typing import Any

from ..utils.logger import get_logger
from ..utils.system.driver_utils import get_driver_path
from .intellicrack_protection_core import DetectionResult, ProtectionAnalysis, ProtectionType
from .unified_protection_engine import UnifiedProtectionEngine, UnifiedProtectionResult


logger = get_logger(__name__)
logger.debug("protection_detector module loaded successfully")


class ProtectionDetector:
    """Run protection detection interface for Intellicrack.

    This class provides a seamless interface to the unified protection engine,
    making it appear as if all detection capabilities are native to Intellicrack.
    """

    def __init__(self, enable_protection: bool = True, enable_heuristics: bool = True) -> None:
        """Initialize the protection detector.

        Args:
            enable_protection: Enable protection analysis
            enable_heuristics: Enable behavioral analysis

        """
        self.engine = UnifiedProtectionEngine(
            enable_protection=enable_protection,
            enable_heuristics=enable_heuristics,
        )

    def detect_protections(self, file_path: str, deep_scan: bool = True) -> ProtectionAnalysis:
        """Analyze a binary file for protections.

        This method maintains backward compatibility with the original ICP detector
        interface while using the unified engine underneath.

        Args:
            file_path: Path to the binary file to analyze
            deep_scan: Perform comprehensive analysis

        Returns:
            ProtectionAnalysis object with all detection results

        Raises:
            FileNotFoundError: If the binary file does not exist at the specified path

        """
        if not os.path.exists(file_path):
            error_msg = f"File not found: {file_path}"
            logger.exception("File not found: %s", file_path)
            raise FileNotFoundError(error_msg)

        # Use unified engine
        unified_result = self.engine.analyze(file_path, deep_scan=deep_scan)

        # Convert to legacy format for compatibility
        return self._convert_to_legacy_format(unified_result)

    def analyze(self, file_path: str, deep_scan: bool = True) -> UnifiedProtectionResult:
        """Perform unified protection analysis.

        This is the modern interface that returns the full unified result.

        Args:
            file_path: Path to the binary file to analyze
            deep_scan: Perform comprehensive analysis

        Returns:
            UnifiedProtectionResult with comprehensive analysis

        """
        return self.engine.analyze(file_path, deep_scan=deep_scan)

    def get_quick_summary(self, file_path: str) -> dict[str, Any]:
        """Get a quick protection summary without deep analysis.

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary with quick summary information

        """
        return self.engine.get_quick_summary(file_path)

    def analyze_directory(self, directory: str, recursive: bool = True, deep_scan: bool = False) -> list[ProtectionAnalysis]:
        """Analyze all executable files in a directory.

        Args:
            directory: Directory path to scan
            recursive: Whether to scan subdirectories
            deep_scan: Perform deep analysis on each file

        Returns:
            List of ProtectionAnalysis results

        """
        logger.info("Starting directory analysis: %s, recursive=%s, deep_scan=%s", directory, recursive, deep_scan)
        results = []
        extensions = [".exe", ".dll", ".sys", ".ocx", ".scr", ".com", ".so", ".dylib"]

        if recursive:
            for root, _dirs, files in os.walk(directory):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in extensions):
                        file_path = os.path.join(root, file)
                        try:
                            analysis = self.detect_protections(file_path, deep_scan=deep_scan)
                            results.append(analysis)
                        except Exception as e:
                            logger.exception("Error analyzing %s: %s", file_path, e)
        else:
            for file in os.listdir(directory):
                if any(file.lower().endswith(ext) for ext in extensions):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        try:
                            analysis = self.detect_protections(file_path, deep_scan=deep_scan)
                            results.append(analysis)
                        except Exception as e:
                            logger.exception("Error analyzing %s: %s", file_path, e)

        logger.info("Completed directory analysis: %s files analyzed successfully", len(results))
        return results

    def get_bypass_strategies(self, file_path: str) -> list[dict[str, Any]]:
        """Get bypass strategies for protections detected in a file.

        Args:
            file_path: Path to the binary file

        Returns:
            List of bypass strategy dictionaries

        """
        result = self.engine.analyze(file_path)
        return result.bypass_strategies

    def _convert_to_legacy_format(self, unified_result: UnifiedProtectionResult) -> ProtectionAnalysis:
        """Convert unified result to legacy ProtectionAnalysis format.

        This ensures backward compatibility with existing code by mapping the modern
        UnifiedProtectionResult structure to the legacy ProtectionAnalysis format.

        Args:
            unified_result: Modern unified protection analysis result

        Returns:
            ProtectionAnalysis: Legacy format analysis object with converted data

        """
        analysis = ProtectionAnalysis(
            file_path=unified_result.file_path,
            file_type=unified_result.file_type,
            architecture=unified_result.architecture,
            is_packed=unified_result.is_packed,
            is_protected=unified_result.is_protected,
        )

        # Convert protections
        for protection in unified_result.protections:
            det_result = DetectionResult(
                name=protection["name"],
                version=protection.get("version"),
                type=self._map_protection_type(protection["type"]),
                confidence=protection.get("confidence", 100.0),
                details=protection.get("details", {}),
                bypass_recommendations=protection.get("bypass_recommendations", []),
            )
            analysis.detections.append(det_result)

        if unified_result.icp_analysis:
            icp_data = unified_result.icp_analysis
            if hasattr(icp_data, "has_overlay"):
                analysis.has_overlay = icp_data.has_overlay
            if hasattr(icp_data, "has_resources"):
                analysis.has_resources = icp_data.has_resources
            if hasattr(icp_data, "entry_point"):
                analysis.entry_point = icp_data.entry_point
            if hasattr(icp_data, "sections"):
                analysis.sections = icp_data.sections
            if hasattr(icp_data, "imports"):
                analysis.imports = icp_data.imports
            if hasattr(icp_data, "strings"):
                analysis.strings = icp_data.strings

        # Add metadata
        analysis.metadata = {
            "analysis_time": unified_result.analysis_time,
            "engines_used": unified_result.engines_used,
            "confidence_score": unified_result.confidence_score,
        }

        return analysis

    def _map_protection_type(self, type_str: str) -> ProtectionType:
        """Map string protection type to enum.

        Converts a string representation of a protection type to the corresponding
        ProtectionType enum value. Performs case-insensitive matching and returns
        UNKNOWN for unmapped types.

        Args:
            type_str: String representation of the protection type

        Returns:
            ProtectionType: Corresponding enum value or UNKNOWN if not found

        """
        type_map = {
            "packer": ProtectionType.PACKER,
            "protector": ProtectionType.PROTECTOR,
            "compiler": ProtectionType.COMPILER,
            "installer": ProtectionType.INSTALLER,
            "library": ProtectionType.LIBRARY,
            "overlay": ProtectionType.OVERLAY,
            "cryptor": ProtectionType.CRYPTOR,
            "dongle": ProtectionType.DONGLE,
            "license": ProtectionType.LICENSE,
            "drm": ProtectionType.DRM,
            "antidebug": ProtectionType.PROTECTOR,
            "obfuscator": ProtectionType.PROTECTOR,
        }

        return type_map.get(type_str.lower(), ProtectionType.UNKNOWN)

    def get_summary(self, analysis: ProtectionAnalysis) -> str:
        """Get a human-readable summary of the analysis.

        Generates a formatted text summary of protection analysis results,
        including file information, detected protections, and confidence scores.

        Args:
            analysis: ProtectionAnalysis object containing detection results

        Returns:
            str: Formatted summary string with file details and protection information

        """
        lines = [f"File: {os.path.basename(analysis.file_path)}"]
        lines.append(f"Type: {analysis.file_type} ({analysis.architecture})")

        if analysis.compiler:
            lines.append(f"Compiler: {analysis.compiler}")

        status_flags = []
        if analysis.is_packed:
            status_flags.append("PACKED")
        if analysis.is_protected:
            status_flags.append("PROTECTED")

        if status_flags:
            lines.append(f"Status: {' | '.join(status_flags)}")

        if analysis.detections:
            lines.append("\nProtections Detected:")
            for det in analysis.detections:
                ver_str = f" v{det.version}" if det.version else ""
                conf_str = f" [{det.confidence:.0f}%]" if det.confidence < 100 else ""
                lines.append(f"   {det.name}{ver_str} ({det.type.value}){conf_str}")

        if "confidence_score" in analysis.metadata:
            lines.append(f"\nOverall Confidence: {analysis.metadata['confidence_score']:.0f}%")

        if "engines_used" in analysis.metadata:
            lines.append(f"Analysis Methods: {', '.join(analysis.metadata['engines_used'])}")

        return "\n".join(lines)

    def export_results(self, analysis: ProtectionAnalysis, output_format: str = "json") -> str:
        """Export analysis results in various formats.

        Args:
            analysis: ProtectionAnalysis to export
            output_format: Format to export ("json", "text", "csv")

        Returns:
            Formatted string of results

        Raises:
            ValueError: If the output_format is not one of the supported formats (json, text, csv)

        """
        if output_format == "json":
            import json

            # Convert to dict for JSON serialization
            data = {
                "file_path": analysis.file_path,
                "file_type": analysis.file_type,
                "architecture": analysis.architecture,
                "is_packed": analysis.is_packed,
                "is_protected": analysis.is_protected,
                "compiler": analysis.compiler,
                "detections": [
                    {
                        "name": d.name,
                        "version": d.version,
                        "type": d.type.value,
                        "confidence": d.confidence,
                        "bypass_recommendations": d.bypass_recommendations,
                    }
                    for d in analysis.detections
                ],
                "metadata": analysis.metadata,
            }
            return json.dumps(data, indent=2)

        if output_format == "text":
            return self.get_summary(analysis)

        if output_format == "csv":
            lines = ["File,Type,Architecture,Protection,Version,Category,Confidence"]
            lines.extend(
                f"{analysis.file_path},{analysis.file_type},{analysis.architecture},{det.name},{det.version or 'N/A'},{det.type.value},{det.confidence:.0f}"
                for det in analysis.detections
            )
            return "\n".join(lines)

        error_msg = f"Unknown output format: {output_format}"
        logger.exception("Unknown output format: %s", output_format)
        raise ValueError(error_msg)

    def detect_virtualization_protection(self, binary_path: str | None = None) -> dict[str, Any]:
        """Detect virtualization-based protections.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "virtualization_detected": False,
            "protection_types": [],
            "indicators": [],
            "confidence": 0.0,
        }

        if binary_path:
            logger.debug("Analyzing virtualization protection for binary: %s", binary_path)

        try:
            vm_indicators = [
                "VirtualBox",
                "VMware",
                "QEMU",
                "Xen",
                "Hyper-V",
                "vbox",
                "vmtoolsd",
                "vmwareuser",
                "qemu-ga",
            ]

            try:
                from intellicrack.handlers.psutil_handler import psutil

                running_processes = [p.info["name"].lower() for p in psutil.process_iter(["name"]) if p.info["name"]]
                for indicator in vm_indicators:
                    if any(indicator.lower() in proc for proc in running_processes):
                        indicators_val = results["indicators"]
                        if isinstance(indicators_val, list):
                            indicators_val.append(f"VM process detected: {indicator}")
                        results["virtualization_detected"] = True
            except ImportError:
                logger.debug("psutil not available for process checking")

            if sys.platform == "win32":
                try:
                    import winreg

                    vm_registry_keys = [
                        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
                        r"SOFTWARE\VMware, Inc.\VMware Tools",
                        r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    ]
                    for key_path in vm_registry_keys:
                        try:
                            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                            indicators_val = results["indicators"]
                            if isinstance(indicators_val, list):
                                indicators_val.append(f"VM registry key found: {key_path}")
                            results["virtualization_detected"] = True
                            winreg.CloseKey(key)
                        except FileNotFoundError:
                            continue
                except ImportError:
                    logger.debug("winreg not available")

            vm_files = [
                "/proc/scsi/scsi",
                "/sys/class/dmi/id/product_name",
                get_driver_path("vboxguest.sys"),
                get_driver_path("vmhgfs.sys"),
            ]
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    try:
                        with open(vm_file, encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            for indicator in vm_indicators:
                                if indicator.lower() in content:
                                    indicators_val = results["indicators"]
                                    if isinstance(indicators_val, list):
                                        indicators_val.append(f"VM indicator in {vm_file}: {indicator}")
                                    results["virtualization_detected"] = True
                    except Exception as e:
                        logger.exception("Exception in virtualization detection: %s", e)

            if results["virtualization_detected"]:
                indicators_val = results["indicators"]
                if isinstance(indicators_val, list):
                    results["confidence"] = min(len(indicators_val) * 0.3, 1.0)
                protection_types_val = results["protection_types"]
                if isinstance(protection_types_val, list):
                    protection_types_val.append("VM Detection")

            logger.info("Virtualization detection complete: %s", results["virtualization_detected"])

        except Exception as e:
            logger.exception("Error in virtualization detection: %s", e)
            results["error"] = str(e)

        return results

    def detect_themida_advanced(self, binary_path: str) -> dict[str, Any]:
        """Advanced Themida/WinLicense detection using virtualization analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detailed Themida analysis results

        """
        try:
            from .themida_analyzer import ThemidaAnalyzer

            analyzer = ThemidaAnalyzer()
            result = analyzer.analyze(binary_path)

            if result.is_protected:
                report = analyzer.get_analysis_report(result)
                return {
                    "detected": True,
                    "version": result.version.value,
                    "vm_architecture": result.vm_architecture.value,
                    "confidence": result.confidence,
                    "handlers_found": len(result.handlers),
                    "vm_sections": result.vm_sections,
                    "devirtualized_sections": len(result.devirtualized_sections),
                    "anti_debug_checks": len(result.anti_debug_locations),
                    "detailed_report": report,
                }
            return {"detected": False, "confidence": 0.0}

        except ImportError:
            logger.warning("Themida analyzer not available, falling back to signature detection")
            return {"detected": False, "error": "Advanced analyzer not available"}
        except Exception as e:
            logger.exception("Themida advanced detection failed: %s", e)
            return {"detected": False, "error": str(e)}

    def detect_denuvo_advanced(self, binary_path: str) -> dict[str, Any]:
        """Advanced Denuvo Anti-Tamper detection using multi-layer analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detailed Denuvo analysis results

        """
        try:
            from .denuvo_analyzer import DenuvoAnalyzer

            analyzer = DenuvoAnalyzer()
            result = analyzer.analyze(binary_path)

            if result.detected:
                version_info = result.version.name if result.version else "Unknown"
                return {
                    "detected": True,
                    "confidence": result.confidence,
                    "version": version_info,
                    "triggers": len(result.triggers),
                    "integrity_checks": len(result.integrity_checks),
                    "timing_checks": len(result.timing_checks),
                    "vm_regions": len(result.vm_regions),
                    "encrypted_sections": len(result.encrypted_sections),
                    "bypass_recommendations": result.bypass_recommendations,
                    "analysis_details": result.analysis_details,
                }
            return {"detected": False, "confidence": 0.0}

        except ImportError:
            logger.warning("Denuvo analyzer not available, falling back to signature detection")
            return {"detected": False, "error": "Advanced analyzer not available"}
        except Exception as e:
            logger.exception("Denuvo advanced detection failed: %s", e)
            return {"detected": False, "error": str(e)}

    def analyze_denuvo_ticket(
        self,
        ticket_data: bytes | str,
    ) -> dict[str, Any]:
        """Analyze Denuvo activation ticket/token.

        Args:
            ticket_data: Raw ticket bytes or path to ticket file

        Returns:
            Detailed ticket analysis results

        """
        try:
            from .denuvo_ticket_analyzer import DenuvoTicketAnalyzer

            analyzer = DenuvoTicketAnalyzer()

            if isinstance(ticket_data, str):
                if os.path.exists(ticket_data):
                    with open(ticket_data, "rb") as f:
                        data = f.read()
                else:
                    logger.exception("Ticket file not found: %s", ticket_data)
                    return {"error": "File not found"}
            else:
                data = ticket_data

            if ticket := analyzer.parse_ticket(data):
                result = {
                    "type": "ticket",
                    "valid": ticket.is_valid,
                    "version": ticket.header.version,
                    "magic": ticket.header.magic.decode("latin-1"),
                    "timestamp": ticket.header.timestamp,
                    "encryption_type": ticket.header.encryption_type,
                    "decrypted": ticket.payload is not None,
                }

                if ticket.payload:
                    result |= {
                        "game_id": ticket.payload.game_id.hex(),
                        "machine_id": ticket.payload.machine_id.combined_hash.hex()[:32],
                        "license_type": ticket.payload.license_data.get("type"),
                        "expiration": ticket.payload.license_data.get("expiration"),
                    }

                return result
            if token := analyzer.parse_token(data):
                return {
                    "type": "token",
                    "game_id": token.game_id.hex(),
                    "machine_id": token.machine_id.hex()[:32],
                    "license_type": token.license_type,
                    "activation_time": token.activation_time,
                    "expiration_time": token.expiration_time,
                    "features_enabled": hex(token.features_enabled),
                }
            return {"error": "Unable to parse as ticket or token"}

        except ImportError:
            logger.warning("Denuvo ticket analyzer not available")
            return {"error": "Ticket analyzer not available"}
        except Exception as e:
            logger.exception("Ticket analysis failed: %s", e)
            return {"error": str(e)}

    def generate_denuvo_activation(
        self,
        request_data: bytes,
        license_type: str = "perpetual",
        duration_days: int = 36500,
    ) -> dict[str, Any]:
        """Generate offline Denuvo activation response.

        Args:
            request_data: Original activation request
            license_type: License type (trial, full, subscription, perpetual)
            duration_days: License duration in days

        Returns:
            Generated activation response data

        """
        try:
            from .denuvo_ticket_analyzer import DenuvoTicketAnalyzer

            analyzer = DenuvoTicketAnalyzer()

            license_map = {
                "trial": analyzer.LICENSE_TRIAL,
                "full": analyzer.LICENSE_FULL,
                "subscription": analyzer.LICENSE_SUBSCRIPTION,
                "perpetual": analyzer.LICENSE_PERPETUAL,
            }

            license_code = license_map.get(license_type.lower(), analyzer.LICENSE_PERPETUAL)

            if response := analyzer.generate_activation_response(
                request_data=request_data,
                license_type=license_code,
                duration_days=duration_days,
            ):
                return {
                    "success": True,
                    "response_id": response.response_id.hex(),
                    "ticket_size": len(response.ticket),
                    "token_size": len(response.token),
                    "timestamp": response.timestamp,
                    "expiration": response.expiration,
                    "license_type": license_type,
                    "ticket": response.ticket.hex(),
                    "token": response.token.hex(),
                }
            return {"success": False, "error": "Failed to generate response"}

        except ImportError:
            logger.warning("Denuvo ticket analyzer not available")
            return {"success": False, "error": "Ticket analyzer not available"}
        except Exception as e:
            logger.exception("Activation generation failed: %s", e)
            return {"success": False, "error": str(e)}

    def forge_denuvo_token(
        self,
        game_id: str,
        machine_id: str,
        license_type: str = "perpetual",
        duration_days: int = 36500,
    ) -> dict[str, Any]:
        """Forge Denuvo activation token.

        Args:
            game_id: Game identifier (hex string)
            machine_id: Machine identifier (hex string)
            license_type: License type
            duration_days: License duration

        Returns:
            Forged token data

        """
        try:
            from .denuvo_ticket_analyzer import DenuvoTicketAnalyzer

            analyzer = DenuvoTicketAnalyzer()

            license_map = {
                "trial": analyzer.LICENSE_TRIAL,
                "full": analyzer.LICENSE_FULL,
                "subscription": analyzer.LICENSE_SUBSCRIPTION,
                "perpetual": analyzer.LICENSE_PERPETUAL,
            }

            license_code = license_map.get(license_type.lower(), analyzer.LICENSE_PERPETUAL)

            game_id_bytes = bytes.fromhex(game_id) if len(game_id) == 32 else (game_id.encode() + b"\x00" * 16)[:16]
            machine_id_bytes = bytes.fromhex(machine_id) if len(machine_id) == 64 else hashlib.sha256(machine_id.encode()).digest()

            if token := analyzer.forge_token(
                game_id=game_id_bytes,
                machine_id=machine_id_bytes,
                license_type=license_code,
                duration_days=duration_days,
            ):
                return {
                    "success": True,
                    "token": token.hex(),
                    "token_size": len(token),
                    "license_type": license_type,
                    "duration_days": duration_days,
                }
            return {"success": False, "error": "Token forging failed"}

        except ImportError:
            logger.warning("Denuvo ticket analyzer not available")
            return {"success": False, "error": "Ticket analyzer not available"}
        except Exception as e:
            logger.exception("Token forging failed: %s", e)
            return {"success": False, "error": str(e)}

    def detect_commercial_protections(self, binary_path: str) -> dict[str, Any]:
        """Detect commercial protections in binary.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results with commercial protections found

        """
        if not os.path.exists(binary_path):
            return {"error": "File not found", "protections": [], "signatures_found": [], "advanced_analysis": {}}

        results: dict[str, Any] = {"protections": [], "signatures_found": [], "advanced_analysis": {}}

        themida_advanced = self.detect_themida_advanced(binary_path)
        if themida_advanced.get("detected"):
            results["protections"].append(themida_advanced["version"])
            results["advanced_analysis"]["themida"] = themida_advanced

        denuvo_advanced = self.detect_denuvo_advanced(binary_path)
        if denuvo_advanced.get("detected"):
            results["protections"].append(denuvo_advanced["version"])
            results["advanced_analysis"]["denuvo"] = denuvo_advanced

        # Commercial protection signatures
        signatures = {
            # Packers
            b"UPX0": "UPX Packer",
            b"UPX!": "UPX Packer",
            b"ASPack": "ASPack Packer",
            b"PEC2": "PECompact",
            b"NSP0": "NsPack",
            b"MPRESS": "MPRESS Packer",
            # Protectors
            b"Themida": "Themida/WinLicense",
            b"WinLicense": "WinLicense",
            b"VProtect": "VMProtect",
            b".vmp0": "VMProtect",
            b".vmp1": "VMProtect",
            b"Obsidium": "Obsidium",
            b"ASProtect": "ASProtect",
            b"Armadillo": "Armadillo",
            b"SecuROM": "SecuROM",
            b"SafeDisc": "SafeDisc",
            b"StarForce": "StarForce",
            b"Denuvo": "Denuvo",
            b"EXECryptor": "EXECryptor",
            b"Enigma": "Enigma Protector",
            b"tElock": "tElock",
            b"PELock": "PELock",
            b"ExeStealth": "ExeStealth",
            b"Yoda's Crypter": "Yoda's Crypter",
            b"nPack": "nPack",
            b"Private exe Protector": "Private exe Protector",
            # Anti-tamper
            b"CrackProof!": "CrackProof",
            b"XProtector": "XProtector",
            b"Security!\x00": "Generic Security Layer",
            # License systems
            b"FLEXnet": "FLEXnet Licensing",
            b"FLEXlm": "FLEXlm Licensing",
            b"HASP": "HASP Protection",
            b"Sentinel": "Sentinel Protection",
            b"WibuKey": "WibuKey/CodeMeter",
            b"CodeMeter": "CodeMeter",
        }

        try:
            with open(binary_path, "rb") as f:
                # Read file in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for signature, protection_name in signatures.items():
                        if signature in chunk:
                            protections_val = results["protections"]
                            if isinstance(protections_val, list) and protection_name not in protections_val:
                                protections_val.append(protection_name)
                                signatures_found_val = results["signatures_found"]
                                if isinstance(signatures_found_val, list):
                                    signatures_found_val.append(
                                        {
                                            "protection": protection_name,
                                            "signature": signature.hex(),
                                            "offset": f.tell() - len(chunk) + chunk.index(signature),
                                        },
                                    )

        except Exception as e:
            logger.exception("Error detecting commercial protections: %s", e)
            results["error"] = str(e)

        return results

    def detect_checksum_verification(self, binary_path: str) -> dict[str, Any]:
        """Detect checksum verification routines.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "has_checksum_verification": False,
            "checksum_types": [],
            "indicators": [],
        }

        checksum_signatures = [
            b"\x81\xc1",  # rol instruction (common in checksums)
            b"\x81\xc9",  # ror instruction
            b"\x33\xc0\x8b",  # xor eax, eax; mov (checksum init)
            b"\x0f\xb6",  # movzx (byte-by-byte processing)
            b"CRC32",
            b"MD5",
            b"SHA1",
            b"SHA256",
            b"checksum",
            b"verify",
            b"integrity",
        ]

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                for sig in checksum_signatures:
                    if sig in content:
                        results["has_checksum_verification"] = True
                        indicators_val = results["indicators"]
                        checksum_types_val = results["checksum_types"]
                        if isinstance(indicators_val, list) and isinstance(checksum_types_val, list):
                            try:
                                sig.decode("ascii")
                                indicators_val.append(f"String reference: {sig.decode('utf-8', errors='ignore')}")
                                if sig in [b"CRC32", b"MD5", b"SHA1", b"SHA256"]:
                                    checksum_types_val.append(sig.decode("utf-8"))
                            except UnicodeDecodeError:
                                indicators_val.append(f"Assembly pattern: {sig.hex()}")

        except Exception as e:
            logger.exception("Error detecting checksum verification: %s", e)
            results["error"] = str(e)

        return results

    def detect_self_healing_code(self, binary_path: str) -> dict[str, Any]:
        """Detect self-healing/self-modifying code.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "has_self_healing": False,
            "techniques": [],
            "indicators": [],
        }

        patterns: dict[bytes, str] = {
            b"\x88": "mov [mem], reg (code modification)",
            b"\x89": "mov [mem], reg32 (code modification)",
            b"\xc6": "mov [mem], imm8 (direct write)",
            b"\xc7": "mov [mem], imm32 (direct write)",
            b"VirtualProtect": "Memory protection change",
            b"WriteProcessMemory": "Process memory write",
            b"NtProtectVirtualMemory": "NT memory protection",
            b"mprotect": "Linux memory protection",
        }

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                for pattern, description in patterns.items():
                    if pattern in content:
                        results["has_self_healing"] = True
                        indicators_val = results["indicators"]
                        techniques_val = results["techniques"]
                        if isinstance(indicators_val, list) and isinstance(techniques_val, list):
                            indicators_val.append(description)

                            if b"Virtual" in pattern or b"Process" in pattern or b"protect" in pattern:
                                techniques_val.append("Memory Protection Manipulation")
                            else:
                                try:
                                    pattern.decode("ascii")
                                except UnicodeDecodeError:
                                    techniques_val.append("Direct Code Modification")

                techniques_final = results["techniques"]
                if isinstance(techniques_final, list):
                    results["techniques"] = list(set(techniques_final))

        except Exception as e:
            logger.exception("Error detecting self-healing code: %s", e)
            results["error"] = str(e)

        return results

    def detect_obfuscation(self, binary_path: str) -> dict[str, Any]:
        """Detect code obfuscation techniques.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "is_obfuscated": False,
            "obfuscation_types": [],
            "entropy_score": 0.0,
            "indicators": [],
        }

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                entropy = self._calculate_entropy(content)
                results["entropy_score"] = entropy

                if entropy > 7.0:
                    results["is_obfuscated"] = True
                    obfuscation_types_val = results["obfuscation_types"]
                    indicators_val = results["indicators"]
                    if isinstance(obfuscation_types_val, list) and isinstance(indicators_val, list):
                        obfuscation_types_val.append("High Entropy (Packed/Encrypted)")
                        indicators_val.append(f"Entropy: {entropy:.2f}")

                obfuscation_patterns: dict[bytes, str] = {
                    b"\xeb\x01": "Junk bytes (EB 01 pattern)",
                    b"\xeb\x02": "Junk bytes (EB 02 pattern)",
                    b"\x90" * 10: "NOP sled",
                    b"\xcc" * 10: "INT3 padding",
                    b".NET Reactor": ".NET Reactor obfuscator",
                    b"ConfuserEx": "ConfuserEx obfuscator",
                    b"Dotfuscator": "Dotfuscator",
                    b"SmartAssembly": "SmartAssembly obfuscator",
                }

                for pattern, description in obfuscation_patterns.items():
                    if pattern in content:
                        results["is_obfuscated"] = True
                        obfuscation_types_val2 = results["obfuscation_types"]
                        indicators_val2 = results["indicators"]
                        if isinstance(obfuscation_types_val2, list) and isinstance(indicators_val2, list):
                            indicators_val2.append(description)
                            if "obfuscator" in description:
                                obfuscation_types_val2.append(description)

                jmp_count = content.count(b"\xeb") + content.count(b"\xe9")
                if jmp_count > len(content) // 100:
                    results["is_obfuscated"] = True
                    obfuscation_types_val3 = results["obfuscation_types"]
                    indicators_val3 = results["indicators"]
                    if isinstance(obfuscation_types_val3, list) and isinstance(indicators_val3, list):
                        obfuscation_types_val3.append("Control Flow Obfuscation")
                        indicators_val3.append(f"High jump density: {jmp_count}")

        except Exception as e:
            logger.exception("Error detecting obfuscation: %s", e)
            results["error"] = str(e)

        return results

    def detect_anti_debugging_techniques(self, binary_path: str) -> dict[str, Any]:
        """Detect anti-debugging techniques.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "has_anti_debug": False,
            "techniques": [],
            "api_calls": [],
            "indicators": [],
        }

        anti_debug_apis = [
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"NtSetInformationThread",
            b"OutputDebugString",
            b"FindWindow",
            b"GetTickCount",
            b"QueryPerformanceCounter",
            b"ZwQuerySystemInformation",
            b"NtQuerySystemInformation",
            b"NtQueryObject",
            b"CloseHandle",
            b"SetUnhandledExceptionFilter",
            b"RtlSetProcessIsCritical",
            b"NtSetDebugFilterState",
        ]

        technique_patterns: dict[bytes, str] = {
            b"\xcc": "INT3 breakpoint detection",
            b"\x64\xa1\x30\x00\x00\x00": "PEB.BeingDebugged check",
            b"\x64\xa1\x18\x00\x00\x00": "PEB.ProcessHeap check",
            b"\x0f\x31": "RDTSC timing check",
            b"\x0f\x01\xc1": "VMCALL detection",
            b"OllyDbg": "OllyDbg detection",
            b"x64dbg": "x64dbg detection",
            b"IDA Pro": "IDA Pro detection",
            b"WinDbg": "WinDbg detection",
            b"DAEMON": "Daemon Tools detection",
        }

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                for api in anti_debug_apis:
                    if api in content:
                        results["has_anti_debug"] = True
                        api_name = api.decode("utf-8", errors="ignore")
                        api_calls_val = results["api_calls"]
                        indicators_val = results["indicators"]
                        if isinstance(api_calls_val, list) and isinstance(indicators_val, list):
                            api_calls_val.append(api_name)
                            indicators_val.append(f"Anti-debug API: {api_name}")

                for pattern, description in technique_patterns.items():
                    if pattern in content:
                        results["has_anti_debug"] = True
                        techniques_val = results["techniques"]
                        indicators_val2 = results["indicators"]
                        if isinstance(techniques_val, list) and isinstance(indicators_val2, list):
                            techniques_val.append(description)
                            try:
                                pattern.decode("ascii")
                                indicators_val2.append(f"String: {pattern.decode('utf-8', errors='ignore')}")
                            except UnicodeDecodeError:
                                indicators_val2.append(f"Assembly pattern: {pattern.hex()}")

                if b"Heap32First" in content or b"Heap32Next" in content:
                    results["has_anti_debug"] = True
                    techniques_val2 = results["techniques"]
                    indicators_val3 = results["indicators"]
                    if isinstance(techniques_val2, list) and isinstance(indicators_val3, list):
                        techniques_val2.append("Heap flag manipulation")
                        indicators_val3.append("Heap walking detection")

        except Exception as e:
            logger.exception("Error detecting anti-debugging: %s", e)
            results["error"] = str(e)

        return results

    def detect_tpm_protection(self, binary_path: str) -> dict[str, Any]:
        """Detect TPM (Trusted Platform Module) protection.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Detection results

        """
        results: dict[str, Any] = {
            "has_tpm_protection": False,
            "tpm_functions": [],
            "indicators": [],
        }

        tpm_signatures = [
            b"Tbsi_",
            b"Tbsip_",
            b"TPM_",
            b"Tpm12_",
            b"Tpm20_",
            b"TpmVirtualSmartCard",
            b"NCryptCreatePersistedKey",
            b"NCryptOpenStorageProvider",
            b"MS_PLATFORM_CRYPTO_PROVIDER",
            b"Microsoft Platform Crypto Provider",
        ]

        try:
            with open(binary_path, "rb") as f:
                content = f.read()

                for sig in tpm_signatures:
                    if sig in content:
                        results["has_tpm_protection"] = True
                        func_name = sig.decode("utf-8", errors="ignore")
                        tpm_functions_val = results["tpm_functions"]
                        indicators_val = results["indicators"]
                        if isinstance(tpm_functions_val, list) and isinstance(indicators_val, list):
                            tpm_functions_val.append(func_name)
                            indicators_val.append(f"TPM function: {func_name}")

        except Exception as e:
            logger.exception("Error detecting TPM protection: %s", e)
            results["error"] = str(e)

        return results

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Computes the Shannon entropy of binary data to detect compression, encryption,
        and obfuscation. Values closer to 8.0 indicate higher entropy (more randomness),
        typical of packed or encrypted code. Returns 0.0 for empty data.

        Args:
            data: Binary data to analyze

        Returns:
            float: Entropy value ranging from 0.0 to 8.0, where higher values indicate greater randomness

        """
        if not data:
            logger.warning("Empty data provided for entropy calculation")
            return 0.0

        import math

        frequency: dict[int, int] = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_all_protections(self, binary_path: str) -> dict[str, Any]:
        """Run all detection methods on a binary.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Combined detection results

        """
        logger.info("Starting comprehensive protection detection for %s", binary_path)

        virtualization_result = self.detect_virtualization_protection(binary_path)
        commercial_result = self.detect_commercial_protections(binary_path)
        checksum_result = self.detect_checksum_verification(binary_path)
        self_healing_result = self.detect_self_healing_code(binary_path)
        obfuscation_result = self.detect_obfuscation(binary_path)
        anti_debug_result = self.detect_anti_debugging_techniques(binary_path)
        tpm_result = self.detect_tpm_protection(binary_path)

        results: dict[str, Any] = {
            "file_path": binary_path,
            "virtualization": virtualization_result,
            "commercial": commercial_result,
            "checksum": checksum_result,
            "self_healing": self_healing_result,
            "obfuscation": obfuscation_result,
            "anti_debug": anti_debug_result,
            "tpm": tpm_result,
        }

        virtualization_detected = bool(virtualization_result.get("virtualization_detected", False))
        commercial_protections = bool(commercial_result.get("protections", []))
        has_checksum = bool(checksum_result.get("has_checksum_verification", False))
        has_self_healing = bool(self_healing_result.get("has_self_healing", False))
        is_obfuscated = bool(obfuscation_result.get("is_obfuscated", False))
        has_anti_debug = bool(anti_debug_result.get("has_anti_debug", False))
        has_tpm = bool(tpm_result.get("has_tpm_protection", False))

        results["summary"] = {
            "is_protected": any([
                virtualization_detected,
                commercial_protections,
                has_checksum,
                has_self_healing,
                is_obfuscated,
                has_anti_debug,
                has_tpm,
            ]),
            "protection_count": sum([
                int(virtualization_detected),
                int(commercial_protections),
                int(has_checksum),
                int(has_self_healing),
                int(is_obfuscated),
                int(has_anti_debug),
                int(has_tpm),
            ]),
        }
        logger.info("Completed comprehensive protection detection: %s protections found", results["summary"]["protection_count"])
        return results


_global_detector: ProtectionDetector | None = None


def get_protection_detector() -> ProtectionDetector:
    """Get or create global protection detector instance.

    Retrieves the singleton ProtectionDetector instance, creating it if necessary.
    This ensures only one detector instance is used throughout the application.

    Returns:
        ProtectionDetector: Global detector instance

    """
    global _global_detector
    if _global_detector is None:
        _global_detector = ProtectionDetector()
    return _global_detector


# Convenience functions for quick analysis
def quick_analyze(file_path: str) -> ProtectionAnalysis:
    """Quick analysis function for one-off use.

    Performs a fast protection analysis without deep scanning, returning legacy
    format results. Useful for quick assessments when speed is prioritized.

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ProtectionAnalysis: Legacy format analysis with detected protections

    """
    detector = get_protection_detector()
    return detector.detect_protections(file_path, deep_scan=False)


def deep_analyze(file_path: str) -> UnifiedProtectionResult:
    """Deep analysis with full unified result.

    Performs comprehensive protection analysis with all detection methods enabled,
    returning the full modern UnifiedProtectionResult format with detailed results.

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        UnifiedProtectionResult: Complete unified analysis with all detection data

    """
    detector = get_protection_detector()
    return detector.analyze(file_path, deep_scan=True)


# Standalone function exports for backward compatibility
def detect_virtualization_protection(binary_path: str | None = None) -> dict[str, Any]:
    """Standalone function for virtualization detection.

    Detects VM-based protections by analyzing running processes, system registry,
    and file system indicators. Works on Windows and Linux platforms.

    Args:
        binary_path: Optional path to binary for additional context

    Returns:
        dict[str, Any]: Detection results with virtualization indicators and confidence

    """
    detector = get_protection_detector()
    return detector.detect_virtualization_protection(binary_path)


def detect_commercial_protections(binary_path: str) -> dict[str, Any]:
    """Standalone function for commercial protection detection.

    Detects commercially available packers, protectors, and license protection systems
    in binary files through signature matching and advanced analysis.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Commercial protections found with signatures and analysis details

    """
    detector = get_protection_detector()
    return detector.detect_commercial_protections(binary_path)


def detect_checksum_verification(binary_path: str) -> dict[str, Any]:
    """Standalone function for checksum verification detection.

    Detects checksum and integrity verification routines including CRC32, MD5, SHA1,
    and SHA256 implementations in binaries.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Checksum detection results with verification methods found

    """
    detector = get_protection_detector()
    return detector.detect_checksum_verification(binary_path)


def detect_self_healing_code(binary_path: str) -> dict[str, Any]:
    """Standalone function for self-healing code detection.

    Detects self-modifying and self-healing code patterns that restore or repair
    the code during execution to prevent static analysis.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Self-healing techniques detected with indicators

    """
    detector = get_protection_detector()
    return detector.detect_self_healing_code(binary_path)


def detect_obfuscation(binary_path: str) -> dict[str, Any]:
    """Standalone function for obfuscation detection.

    Detects code obfuscation techniques including entropy analysis, control flow
    obfuscation, and obfuscator tool signatures.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Obfuscation detection results with entropy and techniques

    """
    detector = get_protection_detector()
    return detector.detect_obfuscation(binary_path)


def detect_anti_debugging_techniques(binary_path: str) -> dict[str, Any]:
    """Standalone function for anti-debugging detection.

    Detects anti-debugging techniques including debugger detection APIs, timing
    checks, and assembler-level anti-debug patterns.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Anti-debugging techniques detected with API calls and patterns

    """
    detector = get_protection_detector()
    return detector.detect_anti_debugging_techniques(binary_path)


def detect_tpm_protection(binary_path: str) -> dict[str, Any]:
    """Standalone function for TPM protection detection.

    Detects Trusted Platform Module (TPM) protection mechanisms and cryptographic
    provider integrations used for secure key storage and activation.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: TPM protection detection results with function signatures

    """
    detector = get_protection_detector()
    return detector.detect_tpm_protection(binary_path)


def detect_all_protections(binary_path: str) -> dict[str, Any]:
    """Standalone function for all protection detection.

    Runs all available protection detection methods on a binary file and combines
    results into a comprehensive protection assessment.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Combined detection results from all analysis methods

    """
    detector = get_protection_detector()
    return detector.detect_all_protections(binary_path)


# Aliases for backward compatibility
detect_anti_debug = detect_anti_debugging_techniques
detect_anti_debugging = detect_anti_debugging_techniques
detect_commercial_protectors = detect_commercial_protections
detect_self_healing = detect_self_healing_code
detect_vm_detection = detect_virtualization_protection


def detect_protection_mechanisms(binary_path: str) -> dict[str, Any]:
    """Detect general protection mechanisms.

    Alias for detect_all_protections providing backward compatibility. Analyzes
    all protection mechanisms in a binary file.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: All detected protection mechanisms

    """
    return detect_all_protections(binary_path)


def detect_packing_methods(binary_path: str) -> dict[str, Any]:
    """Detect packing methods in binary.

    Identifies packing and compression techniques used to obfuscate binaries.
    Filters commercial protection results for packer signatures.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Detected packers and packed status

    """
    results = detect_commercial_protections(binary_path)
    # Filter for packers only
    packers = [p for p in results.get("protections", []) if "Pack" in p or "Compress" in p]
    return {"packers": packers, "is_packed": bool(packers)}


def run_comprehensive_protection_scan(binary_path: str) -> dict[str, Any]:
    """Run comprehensive protection scan.

    Performs exhaustive protection analysis across all detection methods and
    protection categories.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Comprehensive protection scan results

    """
    return detect_all_protections(binary_path)


def scan_for_bytecode_protectors(binary_path: str) -> dict[str, Any]:
    """Scan for bytecode-level protectors.

    Detects bytecode-level protection mechanisms for managed code including .NET
    obfuscators and Java/Python protection tools.

    Args:
        binary_path: Path to the binary file to analyze

    Returns:
        dict[str, Any]: Bytecode protectors detected and protection status

    """
    results = detect_commercial_protections(binary_path)
    # Filter for bytecode protectors
    bytecode_protectors = [
        p for p in results.get("protections", []) if any(x in p for x in [".NET", "Java", "Python", "Dotfuscator", "ConfuserEx"])
    ]
    return {
        "bytecode_protectors": bytecode_protectors,
        "has_bytecode_protection": bool(bytecode_protectors),
    }


def generate_checksum(data: bytes, algorithm: str = "sha256") -> str:
    """Generate checksum for data.

    Computes cryptographic hash of binary data using SHA256. The algorithm parameter
    is accepted for API compatibility but SHA256 is always used for security.

    Args:
        data: Binary data to hash
        algorithm: Hash algorithm identifier (only sha256 is securely supported)

    Returns:
        str: Hexadecimal digest of the SHA256 hash

    """
    # This function has been updated to only use secure hash algorithms
    # MD5 and SHA1 detection now uses SHA256 for internal processing
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        detector = ProtectionDetector()

        logger.info("=== QUICK ANALYSIS ===")
        summary = detector.get_quick_summary(target_file)
        logger.info("Protected: %s", summary["protected"])
        logger.info("Main Protection: %s", summary.get("main_protection", "None"))
        logger.info("Confidence: %.0f%%", summary["confidence"])

        logger.info("\n=== FULL ANALYSIS ===")
        analysis = detector.detect_protections(target_file)
        logger.info("%s", detector.get_summary(analysis))

        logger.info("\n=== BYPASS STRATEGIES ===")
        strategies = detector.get_bypass_strategies(target_file)
        for strategy in strategies:
            logger.info("\n%s (%s)", strategy["name"], strategy["difficulty"])
            logger.info("  %s", strategy["description"])
            if "tools" in strategy:
                logger.info("  Tools: %s", ", ".join(strategy["tools"]))
    else:
        logger.info("Usage: python protection_detector.py <binary_file>")
