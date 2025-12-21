"""Binary analysis utility functions.

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

from __future__ import annotations

import logging
import math
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from intellicrack.utils.subprocess_security import secure_run


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import ModuleType

logger = logging.getLogger(__name__)


class OrchestratorLike(Protocol):
    """Protocol defining the interface for orchestrator objects in script generation workflows.

    This protocol specifies the contract that orchestrator implementations must follow
    for autonomous script generation and processing in the licensing cracking analysis pipeline.
    """

    def process_request(self, request: str) -> dict[str, Any]:
        """Process an autonomous script generation request.

        Args:
            request: The script generation request description

        Returns:
            Dictionary containing the result of processing the request

        """
        pass


class PEFile(Protocol):
    """Protocol for PE file objects from pefile module."""

    DIRECTORY_ENTRY_RESOURCE: Any

    def __init__(self, filename: str) -> None: ...


class ResourceDirectory(Protocol):
    """Protocol for PE resource directory objects."""

    entries: list[Any]


pefile_module: ModuleType | None = None
lief_module: ModuleType | None = None
ELFFile_class: type[Any] | None = None
MachO_class: type[Any] | None = None
capstone_module: ModuleType | None = None

create_performance_optimizer_func: Callable[..., Any] | None = None
PERFORMANCE_OPTIMIZER_AVAILABLE = False

try:
    from ..runtime.performance_optimizer import create_performance_optimizer as _create_optimizer

    create_performance_optimizer_func = _create_optimizer
    PERFORMANCE_OPTIMIZER_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)


try:
    from intellicrack.handlers.pefile_handler import pefile as _pefile

    pefile_module = _pefile
    PEFILE_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)
    PEFILE_AVAILABLE = False

try:
    from intellicrack.handlers.lief_handler import (
        HAS_LIEF,
        lief as _lief,
    )

    lief_module = _lief
    LIEF_AVAILABLE = HAS_LIEF
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)
    LIEF_AVAILABLE = False
    HAS_LIEF = False

try:
    from intellicrack.handlers.pyelftools_handler import (
        HAS_PYELFTOOLS,
        ELFFile as _ELFFile,
    )

    ELFFile_class = _ELFFile
    PYELFTOOLS_AVAILABLE = HAS_PYELFTOOLS
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)
    PYELFTOOLS_AVAILABLE = False
    HAS_PYELFTOOLS = False

try:
    from macholib.MachO import MachO as _MachO

    MachO_class = _MachO
    MACHOLIB_AVAILABLE = True
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)
    MACHOLIB_AVAILABLE = False

try:
    from intellicrack.handlers.capstone_handler import capstone as _capstone

    capstone_module = _capstone
    HAS_CAPSTONE = True
except ImportError as e:
    logger.exception("Import error in binary_analysis: %s", e)
    HAS_CAPSTONE = False


def analyze_binary_optimized(binary_path: str, detailed: bool = True, use_performance_optimizer: bool = True) -> dict[str, Any]:
    """Optimized binary analysis with performance management for large files.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis
        use_performance_optimizer: Whether to use performance optimizations

    Returns:
        Dictionary containing analysis results

    """
    if not os.path.exists(binary_path):
        return {"error": f"File not found: {binary_path}"}

    file_size = Path(binary_path).stat().st_size
    file_size_mb = file_size / 1024 / 1024

    logger.info("Starting optimized analysis of %s (%.1fMB)", Path(binary_path).name, file_size_mb)

    # Use performance optimizer for large files
    if use_performance_optimizer and PERFORMANCE_OPTIMIZER_AVAILABLE and file_size_mb > 50:
        return _analyze_with_performance_optimizer(binary_path, detailed)
    return analyze_binary(binary_path, detailed)


def _analyze_with_performance_optimizer(binary_path: str, detailed: bool) -> dict[str, Any]:
    """Analyze binary using performance optimizer."""
    if create_performance_optimizer_func is None:
        return analyze_binary(binary_path, detailed)

    try:
        optimizer = create_performance_optimizer_func(max_memory_mb=4096)

        analysis_functions: Sequence[Callable[[bytes, dict[str, Any] | None], dict[str, Any]]] = [
            _optimized_basic_analysis,
            _optimized_string_analysis,
            _optimized_entropy_analysis,
        ]

        if detailed:
            analysis_functions = [
                *list(analysis_functions),
                _optimized_section_analysis,
                _optimized_import_analysis,
                _optimized_pattern_analysis,
            ]

        optimizer_results: dict[str, Any] = cast(
            "dict[str, Any]",
            optimizer.optimize_analysis(binary_path, list(analysis_functions)),
        )

        perf_metrics: dict[str, Any] = optimizer_results.get("performance_metrics", {})
        results: dict[str, Any] = {
            "file_path": binary_path,
            "file_size": Path(binary_path).stat().st_size,
            "analysis_type": "optimized",
            "performance_metrics": perf_metrics,
            "cache_efficiency": perf_metrics.get("cache_efficiency", 0.0),
            "strategy_used": optimizer_results.get("strategy", "unknown"),
        }

        analysis_results: dict[str, Any] = optimizer_results.get("analysis_results", {})
        for func_name, func_result in analysis_results.items():
            if isinstance(func_result, dict) and func_result.get("status") == "success":
                results[func_name] = func_result
            else:
                error_msg = func_result.get("error", "unknown") if isinstance(func_result, dict) else "unknown"
                logger.warning("Analysis function %s failed: %s", func_name, error_msg)

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in performance-optimized analysis: %s", e)
        return analyze_binary(binary_path, detailed)


def analyze_binary(binary_path: str, detailed: bool = True, enable_ai_integration: bool = True) -> dict[str, Any]:
    """Run binary analysis orchestrator.

    Identifies the binary format and performs appropriate analysis.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis
        enable_ai_integration: Whether to enable AI script generation integration

    Returns:
        Dict containing analysis results

    """
    if not binary_path:
        return {"error": "Empty path provided"}

    if not os.path.exists(binary_path):
        return {"error": f"Binary not found: {binary_path}"}

    # Identify format
    binary_format = identify_binary_format(binary_path)

    # Route to appropriate analyzer
    if binary_format == "PE":
        results = analyze_pe(binary_path, detailed)
    elif binary_format == "ELF":
        results = analyze_elf(binary_path, detailed)
    elif binary_format == "MACHO":
        results = analyze_macho(binary_path, detailed)
    else:
        results = {
            "format": binary_format,
            "error": f"Unsupported format: {binary_format}",
            "basic_info": get_basic_file_info(binary_path),
        }

    # AI Integration: Trigger AI script generation workflow if enabled
    if enable_ai_integration and not results.get("error"):
        results = _integrate_ai_script_generation(results, binary_path)

    return results


def _integrate_ai_script_generation(analysis_results: dict[str, Any], binary_path: str) -> dict[str, Any]:
    """Integrate AI script generation workflow with binary analysis results.

    Args:
        analysis_results: Results from binary analysis
        binary_path: Path to the analyzed binary

    Returns:
        Enhanced analysis results with AI script generation suggestions

    """
    try:
        # Import AI components
        from ...ai.orchestrator import get_orchestrator

        logger.info("Integrating AI script generation for %s", binary_path)

        # Get AI orchestrator
        orchestrator = get_orchestrator()
        if not orchestrator:
            logger.warning("AI orchestrator not available for script generation")
            return analysis_results

        # Analyze binary characteristics to determine script generation strategy
        ai_suggestions = _generate_ai_script_suggestions(analysis_results, binary_path)

        # Add AI integration results to analysis
        analysis_results["ai_integration"] = {
            "enabled": True,
            "script_suggestions": ai_suggestions,
            "recommended_actions": _get_recommended_ai_actions(analysis_results),
            "auto_generation_candidates": _identify_auto_generation_candidates(analysis_results),
        }

        # Trigger autonomous script generation for high-confidence cases
        if ai_suggestions.get("auto_generate_confidence", 0) > 0.8:
            logger.info("High confidence detected - triggering autonomous script generation")
            _trigger_autonomous_script_generation(orchestrator, analysis_results, binary_path)

        logger.info("AI script generation integration completed successfully")

    except Exception as e:
        logger.exception("Error in AI script generation integration: %s", e)
        analysis_results["ai_integration"] = {"enabled": False, "error": str(e)}

    return analysis_results


def _generate_ai_script_suggestions(analysis_results: dict[str, Any], binary_path: str) -> dict[str, Any]:
    """Generate AI script suggestions based on analysis results."""
    logger.debug("Generating AI script suggestions for binary: %s", binary_path)
    frida_scripts: list[dict[str, Any]] = []
    ghidra_scripts: list[dict[str, Any]] = []
    auto_generate_confidence: float = 0.0
    priority_targets: list[str] = []

    try:
        if "license_checks" in analysis_results or "protection" in analysis_results:
            frida_scripts.append(
                {
                    "type": "license_bypass",
                    "description": "License validation bypass script",
                    "confidence": 0.9,
                    "complexity": "advanced",
                },
            )
            auto_generate_confidence = max(auto_generate_confidence, 0.85)
            priority_targets.append("license_validation")

        if analysis_results.get("anti_debug") or "debugger" in str(analysis_results).lower():
            frida_scripts.append(
                {
                    "type": "anti_debug_bypass",
                    "description": "Anti-debugging bypass script",
                    "confidence": 0.8,
                    "complexity": "moderate",
                },
            )
            auto_generate_confidence = max(auto_generate_confidence, 0.75)
            priority_targets.append("anti_debugging")

        network_indicators = ["wininet", "urlmon", "ws2_32", "socket", "connect"]
        if any(indicator in str(analysis_results).lower() for indicator in network_indicators):
            frida_scripts.append(
                {
                    "type": "network_bypass",
                    "description": "Network validation bypass script",
                    "confidence": 0.7,
                    "complexity": "advanced",
                },
            )
            auto_generate_confidence = max(auto_generate_confidence, 0.65)
            priority_targets.append("network_validation")

        crypto_indicators = ["crypto", "encrypt", "decrypt", "hash", "aes", "rsa"]
        if any(indicator in str(analysis_results).lower() for indicator in crypto_indicators):
            ghidra_scripts.append(
                {
                    "type": "crypto_analysis",
                    "description": "Cryptographic function analysis script",
                    "confidence": 0.8,
                    "complexity": "advanced",
                },
            )
            priority_targets.append("cryptographic_functions")

        trial_indicators = ["trial", "expire", "time", "date", "demo"]
        if any(indicator in str(analysis_results).lower() for indicator in trial_indicators):
            frida_scripts.append(
                {
                    "type": "trial_bypass",
                    "description": "Trial/time restriction bypass script",
                    "confidence": 0.85,
                    "complexity": "moderate",
                },
            )
            auto_generate_confidence = max(auto_generate_confidence, 0.8)
            priority_targets.append("trial_restrictions")

    except Exception as e:
        logger.exception("Error generating AI script suggestions: %s", e)

    return {
        "frida_scripts": frida_scripts,
        "ghidra_scripts": ghidra_scripts,
        "auto_generate_confidence": auto_generate_confidence,
        "priority_targets": priority_targets,
    }


def _get_recommended_ai_actions(analysis_results: dict[str, Any]) -> list[str]:
    """Get recommended AI actions based on analysis results."""
    actions: list[str] = [
        "Generate comprehensive Frida hooks for key functions",
        "Create Ghidra scripts for static analysis automation",
    ]

    try:
        binary_format = str(analysis_results.get("format", "")).upper()
        if binary_format == "ELF":
            actions.extend([
                "Analyze ELF symbols and dynamic linking",
                "Generate GOT (Global Offset Table) manipulation scripts",
            ])
        elif binary_format == "PE":
            actions.extend(
                (
                    "Analyze PE imports and exports for bypass opportunities",
                    "Generate IAT (Import Address Table) hook scripts",
                )
            )
        if analysis_results.get("protection"):
            actions.extend(
                (
                    "Generate multi-layer protection bypass strategy",
                    "Create adaptive bypass scripts with fallback mechanisms",
                )
            )
    except Exception as e:
        logger.exception("Error getting recommended AI actions: %s", e)

    return actions


def _identify_auto_generation_candidates(analysis_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Identify candidates for automatic script generation."""
    candidates: list[dict[str, Any]] = []

    try:
        if imports := analysis_results.get("imports"):
            protection_apis = [
                "GetTickCount",
                "GetSystemTime",
                "RegOpenKey",
                "RegQueryValue",
                "CreateMutex",
                "FindWindow",
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
            ]

            candidates.extend(
                {
                    "target": api,
                    "type": "api_hook",
                    "confidence": 0.9,
                    "script_type": "frida",
                    "description": f"Automatic {api} bypass hook",
                }
                for api in protection_apis
                if any(api.lower() in str(imp).lower() for imp in imports)
            )

        entropy_val = analysis_results.get("entropy")
        if isinstance(entropy_val, (int, float)) and entropy_val > 7.5:
            candidates.append(
                {
                    "target": "unpacking",
                    "type": "dynamic_unpacker",
                    "confidence": 0.8,
                    "script_type": "frida",
                    "description": "Automatic unpacking assistance script",
                },
            )

    except Exception as e:
        logger.exception("Error identifying auto-generation candidates: %s", e)

    return candidates


def _trigger_autonomous_script_generation(orchestrator: Any, analysis_results: dict[str, Any], binary_path: str) -> None:
    """Trigger autonomous script generation for high-confidence scenarios.

    Args:
        orchestrator: Orchestrator instance for managing script generation workflow
        analysis_results: Dictionary containing analysis findings and metrics
        binary_path: Path to the binary being analyzed

    """
    try:
        from ...ai.script_generation_agent import AIAgent

        agent = AIAgent(orchestrator=orchestrator, cli_interface=None)

        # Build autonomous generation request
        suggestions = analysis_results["ai_integration"]["script_suggestions"]
        if priority_targets := suggestions.get("priority_targets", []):
            target_description = ", ".join(priority_targets)
            autonomous_request = (
                f"Automatically generate bypass scripts for {binary_path}. "
                f"Priority targets: {target_description}. "
                f"Use autonomous mode with testing and refinement."
            )

            logger.info("Triggering autonomous script generation: %s", autonomous_request)

            # Process request in background (non-blocking)
            import threading

            thread = threading.Thread(target=agent.process_request, args=(autonomous_request,), daemon=True)
            thread.start()

            # Update analysis results to indicate autonomous generation started
            analysis_results["ai_integration"]["autonomous_generation"] = {
                "started": True,
                "request": autonomous_request,
                "targets": priority_targets,
            }

    except Exception as e:
        logger.exception("Error triggering autonomous script generation: %s", e)


def identify_binary_format(binary_path: str) -> str:
    """Identify the format of a binary file.

    Args:
        binary_path: Path to the binary file

    Returns:
        String indicating the format (PE, ELF, MACHO, UNKNOWN)

    """
    try:
        with open(binary_path, "rb") as f:
            # Read magic bytes
            magic = f.read(4)

            # Check for PE
            if magic[:2] == b"MZ":
                # Verify PE signature
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) == b"PE\x00\x00":
                    return "PE"

            # Check for ELF
            elif magic == b"\x7fELF":
                return "ELF"

            # Check for Mach-O
            elif magic in [
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",  # 32-bit
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",  # 64-bit
                b"\xca\xfe\xba\xbe",
                b"\xbe\xba\xfe\xca",
            ]:  # FAT
                return "MACHO"

            # Check for Java class
            elif magic == b"\xca\xfe\xba\xbe":
                return "CLASS"

            # Check for .NET
            f.seek(0)
            data = f.read(512)
            if b"mscoree.dll" in data or b".NET" in data:
                return "DOTNET"

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error identifying binary format: %s", e)

    return "UNKNOWN"


def analyze_pe(binary_path: str, detailed: bool = True) -> dict[str, Any]:
    """Analyze a PE (Windows) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing PE analysis results

    """
    _ = detailed
    if not PEFILE_AVAILABLE or pefile_module is None:
        return {
            "format": "PE",
            "error": "pefile module not available",
            "basic_info": get_basic_file_info(binary_path),
        }

    try:
        pe = pefile_module.PE(binary_path)

        sections_list: list[dict[str, Any]] = []
        imports_list: list[dict[str, Any]] = []
        exports_list: list[dict[str, Any]] = []
        suspicious_list: list[str] = []

        info: dict[str, Any] = {
            "format": "PE",
            "machine": get_machine_type(getattr(pe.FILE_HEADER, "Machine", 0)),
            "timestamp": time.ctime(getattr(pe.FILE_HEADER, "TimeDateStamp", 0)),
            "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", 0),
            "characteristics": getattr(pe.FILE_HEADER, "Characteristics", 0),
            "dll": bool(getattr(pe.FILE_HEADER, "Characteristics", 0) & 0x2000),
            "sections": sections_list,
            "imports": imports_list,
            "exports": exports_list,
            "resources": [],
            "suspicious_indicators": suspicious_list,
        }

        for section in pe.sections:
            section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy_val: float = section.get_entropy() if hasattr(section, "get_entropy") else 0.0
            section_info: dict[str, Any] = {
                "name": section_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "entropy": entropy_val,
            }
            sections_list.append(section_info)

            if entropy_val > 7.0:
                suspicious_list.append(f"High entropy section '{section_name}': {entropy_val:.2f}")

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                functions_list: list[str] = []
                import_info: dict[str, Any] = {"dll": dll_name, "functions": functions_list}

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        functions_list.append(func_name)
                        check_suspicious_import(func_name, dll_name, suspicious_list)

                imports_list.append(import_info)

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal_{exp.ordinal}"
                export_info: dict[str, Any] = {
                    "name": export_name,
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    "ordinal": exp.ordinal,
                }
                exports_list.append(export_info)

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            info["resources"] = analyze_pe_resources(pe)

        entry_point = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
        if entry_point == 0:
            suspicious_list.append("Entry point is 0")

        image_size = getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0)
        if image_size > 100 * 1024 * 1024:
            suspicious_list.append(f"Large image size: {image_size / (1024 * 1024):.2f} MB")

        return info

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing PE binary: %s", e)
        return {"format": "PE", "error": str(e), "basic_info": get_basic_file_info(binary_path)}


def analyze_elf(binary_path: str, detailed: bool = True) -> dict[str, Any]:
    """Analyze an ELF (Linux) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing ELF analysis results

    """
    if LIEF_AVAILABLE and lief_module is not None:
        return analyze_elf_with_lief(binary_path, detailed)
    if PYELFTOOLS_AVAILABLE and ELFFile_class is not None:
        return analyze_elf_with_pyelftools(binary_path, detailed)
    return {
        "format": "ELF",
        "error": "No ELF analysis library available",
        "basic_info": get_basic_file_info(binary_path),
    }


def analyze_elf_with_lief(binary_path: str, detailed: bool) -> dict[str, Any]:
    """Analyze ELF using LIEF library."""
    _ = detailed
    if lief_module is None:
        return {"format": "ELF", "error": "LIEF not available"}

    try:
        if not hasattr(lief_module, "parse"):
            error_msg = "lief.parse not available"
            logger.error(error_msg)
            raise ImportError(error_msg)

        binary = lief_module.parse(binary_path)
        if binary is None:
            return {"format": "ELF", "error": "Failed to parse binary"}

        sections_list: list[dict[str, Any]] = []
        symbols_list: list[dict[str, Any]] = []
        libraries_list: list[str] = []
        suspicious_list: list[str] = []

        machine_type = getattr(binary.header, "machine_type", None)
        machine_str = str(machine_type.name) if machine_type and hasattr(machine_type, "name") else str(machine_type)

        identity_class = getattr(binary.header, "identity_class", None)
        class_str = "64-bit" if identity_class and "ELF64" in str(identity_class) else "32-bit"

        file_type = getattr(binary.header, "file_type", None)
        type_str = str(file_type.name) if file_type and hasattr(file_type, "name") else str(file_type)

        entrypoint = getattr(binary, "entrypoint", 0)

        info: dict[str, Any] = {
            "format": "ELF",
            "machine": machine_str,
            "class": class_str,
            "type": type_str,
            "entry_point": hex(entrypoint) if isinstance(entrypoint, int) else "0x0",
            "sections": sections_list,
            "symbols": symbols_list,
            "libraries": libraries_list,
            "suspicious_indicators": suspicious_list,
        }

        for section in binary.sections:
            section_name = getattr(section, "name", "")
            section_type_val = getattr(section, "type", None)
            section_type_str = str(section_type_val) if section_type_val else "unknown"
            vaddr = getattr(section, "virtual_address", 0)
            section_size = getattr(section, "size", 0)
            section_flags = getattr(section, "flags", 0)
            section_entropy: float = float(getattr(section, "entropy", 0.0))

            section_info: dict[str, Any] = {
                "name": section_name,
                "type": section_type_str,
                "address": hex(vaddr) if isinstance(vaddr, int) else "0x0",
                "size": section_size,
                "flags": section_flags,
                "entropy": section_entropy,
            }
            sections_list.append(section_info)

            if section_name in [".packed", ".encrypted", ".obfuscated"]:
                suspicious_list.append(f"Suspicious section name: {section_name}")

        if hasattr(binary, "dynamic_symbols"):
            for symbol in binary.dynamic_symbols:
                if symbol_name := getattr(symbol, "name", ""):
                    symbol_value = getattr(symbol, "value", 0)
                    symbol_type = getattr(symbol, "type", None)
                    symbols_list.append({
                        "name": symbol_name,
                        "value": hex(symbol_value) if isinstance(symbol_value, int) else "0x0",
                        "type": str(symbol_type),
                    })

        if hasattr(binary, "libraries"):
            for lib in binary.libraries:
                libraries_list.append(str(lib))

        return info

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing ELF with LIEF: %s", e)
        return {"format": "ELF", "error": str(e)}


def analyze_elf_with_pyelftools(binary_path: str, detailed: bool) -> dict[str, Any]:
    """Analyze ELF using pyelftools."""
    _ = detailed
    if ELFFile_class is None:
        return {"format": "ELF", "error": "pyelftools not available"}

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile_class(f)

            sections_list: list[dict[str, Any]] = []
            suspicious_list: list[str] = []

            elf_header = getattr(elf, "header", {})
            elf_class = getattr(elf, "elfclass", 0)

            info: dict[str, Any] = {
                "format": "ELF",
                "machine": elf_header.get("e_machine", "unknown"),
                "class": elf_class,
                "type": elf_header.get("e_type", "unknown"),
                "entry_point": hex(elf_header.get("e_entry", 0)),
                "sections": sections_list,
                "suspicious_indicators": suspicious_list,
            }

            if hasattr(elf, "iter_sections"):
                for section in elf.iter_sections():
                    section_name = getattr(section, "name", "")
                    section_dict = dict(section) if hasattr(section, "__iter__") else {}
                    section_info: dict[str, Any] = {
                        "name": section_name,
                        "type": section_dict.get("sh_type", "unknown"),
                        "address": hex(section_dict.get("sh_addr", 0)),
                        "size": section_dict.get("sh_size", 0),
                    }
                    sections_list.append(section_info)

            return info

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing ELF with pyelftools: %s", e)
        return {"format": "ELF", "error": str(e)}


def analyze_macho(binary_path: str, detailed: bool = True) -> dict[str, Any]:
    """Analyze a Mach-O (macOS) binary.

    Args:
        binary_path: Path to the binary file
        detailed: Whether to perform detailed analysis

    Returns:
        Dict containing Mach-O analysis results

    """
    if LIEF_AVAILABLE and lief_module is not None:
        return analyze_macho_with_lief(binary_path, detailed)
    if MACHOLIB_AVAILABLE and MachO_class is not None:
        return analyze_macho_with_macholib(binary_path, detailed)
    return {
        "format": "MACHO",
        "error": "No Mach-O analysis library available",
        "basic_info": get_basic_file_info(binary_path),
    }


def analyze_macho_with_lief(binary_path: str, detailed: bool) -> dict[str, Any]:
    """Analyze Mach-O using LIEF library."""
    _ = detailed
    if lief_module is None:
        return {"format": "MACHO", "error": "LIEF not available"}

    try:
        if not hasattr(lief_module, "parse"):
            error_msg = "lief.parse not available"
            logger.error(error_msg)
            raise ImportError(error_msg)

        binary = lief_module.parse(binary_path)
        if binary is None:
            return {"format": "MACHO", "error": "Failed to parse binary"}

        headers_list: list[dict[str, Any]] = []
        segments_list: list[dict[str, Any]] = []
        symbols_list: list[dict[str, Any]] = []
        libraries_list: list[str] = []

        info: dict[str, Any] = {
            "format": "MACHO",
            "headers": headers_list,
            "segments": segments_list,
            "symbols": symbols_list,
            "libraries": libraries_list,
        }

        if header := getattr(binary, "header", None):
            magic_val = getattr(header, "magic", 0)
            cpu_type = getattr(header, "cpu_type", None)
            file_type = getattr(header, "file_type", None)

            header_info: dict[str, Any] = {
                "magic": hex(magic_val) if isinstance(magic_val, int) else str(magic_val),
                "cpu_type": str(cpu_type.name) if cpu_type and hasattr(cpu_type, "name") else str(cpu_type),
                "file_type": str(file_type.name) if file_type and hasattr(file_type, "name") else str(file_type),
            }
            headers_list.append(header_info)

        if hasattr(binary, "segments"):
            for segment in binary.segments:
                segment_name = getattr(segment, "name", "")
                segment_vaddr = getattr(segment, "virtual_address", 0)
                segment_vsize = getattr(segment, "virtual_size", 0)
                section_list: list[dict[str, Any]] = []

                segment_info: dict[str, Any] = {
                    "name": segment_name,
                    "address": hex(segment_vaddr) if isinstance(segment_vaddr, int) else "0x0",
                    "size": segment_vsize,
                    "sections": section_list,
                }

                if hasattr(segment, "sections"):
                    for section in segment.sections:
                        sect_name = getattr(section, "name", "")
                        sect_vaddr = getattr(section, "virtual_address", 0)
                        sect_size = getattr(section, "size", 0)

                        section_info: dict[str, Any] = {
                            "name": sect_name,
                            "address": hex(sect_vaddr) if isinstance(sect_vaddr, int) else "0x0",
                            "size": sect_size,
                        }
                        section_list.append(section_info)

                segments_list.append(segment_info)

        return info

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing Mach-O with LIEF: %s", e)
        return {"format": "MACHO", "error": str(e)}


def analyze_macho_with_macholib(binary_path: str, detailed: bool) -> dict[str, Any]:
    """Analyze Mach-O using macholib."""
    _ = detailed
    if MachO_class is None:
        return {"format": "MACHO", "error": "macholib not available"}

    try:
        macho = MachO_class(binary_path)

        headers_list: list[dict[str, Any]] = []
        segments_list: list[dict[str, Any]] = []
        libraries_list: list[str] = []

        info: dict[str, Any] = {
            "format": "MACHO",
            "headers": headers_list,
            "segments": segments_list,
            "libraries": libraries_list,
        }

        for header in macho.headers:
            magic_attr = getattr(header, "MH_MAGIC", 0)
            inner_header = getattr(header, "header", None)
            cputype = getattr(inner_header, "cputype", 0) if inner_header else 0
            cpusubtype = getattr(inner_header, "cpusubtype", 0) if inner_header else 0
            filetype = getattr(inner_header, "filetype", 0) if inner_header else 0

            header_info: dict[str, Any] = {
                "magic": hex(magic_attr) if isinstance(magic_attr, int) else str(magic_attr),
                "cpu_type": cputype,
                "cpu_subtype": cpusubtype,
                "filetype": filetype,
            }
            headers_list.append(header_info)

        return info

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing Mach-O with macholib: %s", e)
        return {"format": "MACHO", "error": str(e)}


def analyze_patterns(binary_path: str, patterns: list[bytes] | None = None) -> dict[str, Any]:
    """Analyze patterns in a binary file.

    Args:
        binary_path: Path to the binary file
        patterns: List of byte patterns to search for (default: common patterns)

    Returns:
        Dict containing pattern analysis results

    """
    if patterns is None:
        patterns = [
            b"license",
            b"trial",
            b"expire",
            b"activation",
            b"register",
            b"serial",
            b"crack",
            b"patch",
            b"keygen",
            b"LICENSE",
            b"TRIAL",
            b"EXPIRED",
        ]

    matches_list: list[dict[str, Any]] = []
    statistics: dict[str, int] = {}

    results: dict[str, Any] = {
        "total_patterns": len(patterns),
        "matches": matches_list,
        "statistics": statistics,
    }

    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        for pattern in patterns:
            pattern_matches: list[dict[str, str]] = []
            search_offset = 0

            while True:
                pos = data.find(pattern, search_offset)
                if pos == -1:
                    break

                context_start = max(0, pos - 20)
                context_end = min(len(data), pos + len(pattern) + 20)
                context = data[context_start:context_end]

                pattern_matches.append(
                    {
                        "offset": hex(pos),
                        "pattern": pattern.decode("utf-8", errors="ignore"),
                        "context": context.hex(),
                    },
                )

                search_offset = pos + 1

            if pattern_matches:
                matches_list.append(
                    {
                        "pattern": pattern.decode("utf-8", errors="ignore"),
                        "count": len(pattern_matches),
                        "locations": pattern_matches[:10],
                    },
                )

        statistics["total_matches"] = sum(m.get("count", 0) for m in matches_list if isinstance(m.get("count"), int))
        statistics["unique_patterns_found"] = len(matches_list)

        return results

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing patterns: %s", e)
        return {"error": str(e)}


def analyze_traffic(pcap_file: str | None = None, interface: str | None = None, duration: int = 60) -> dict[str, Any]:
    """Analyze network traffic for license-related communications.

    Args:
        pcap_file: Path to PCAP file to analyze (optional)
        interface: Network interface to capture from (optional)
        duration: Duration to capture in seconds (default: 60)

    Returns:
        Dict containing traffic analysis results

    """
    _ = duration
    license_servers: list[dict[str, Any]] = []
    suspicious_connections: list[dict[str, Any]] = []
    protocols: dict[str, int] = {}
    packets_analyzed: int = 0

    results: dict[str, Any] = {
        "source": pcap_file or interface or "unknown",
        "packets_analyzed": packets_analyzed,
        "license_servers": license_servers,
        "suspicious_connections": suspicious_connections,
        "protocols": protocols,
    }

    license_ports: dict[int, str] = {
        27000: "FlexLM",
        27001: "FlexLM",
        1947: "HASP/Sentinel",
        8080: "Generic HTTP",
        443: "HTTPS",
        5053: "RLM",
        2080: "Autodesk",
        49152: "CodeMeter",
    }

    try:
        if "scapy" in sys.modules or _try_import_scapy():
            try:
                from scapy.all import rdpcap, sniff
            except ImportError as e:
                logger.exception("Import error in binary_analysis: %s", e)
                return {"network_connections": [], "protocols": [], "error": "scapy not available"}

            packet_list: list[Any] = []
            if pcap_file and os.path.exists(pcap_file):
                packet_list = list(rdpcap(pcap_file))
            elif interface:
                packet_list = list(sniff(iface=interface, count=100, timeout=10))

            for packet in packet_list:
                packets_analyzed += 1

                if not hasattr(packet, "haslayer"):
                    continue

                ip_layer = getattr(packet, "payload", None)
                if ip_layer is None or not hasattr(ip_layer, "src"):
                    continue

                src_ip: str = str(getattr(ip_layer, "src", ""))
                dst_ip: str = str(getattr(ip_layer, "dst", ""))

                src_port: int = 0
                dst_port: int = 0
                protocol: str = ""

                tcp_layer = getattr(ip_layer, "payload", None)
                if tcp_layer and hasattr(tcp_layer, "sport") and hasattr(tcp_layer, "dport"):
                    tcp_class_name = type(tcp_layer).__name__
                    if "TCP" in tcp_class_name:
                        src_port = int(getattr(tcp_layer, "sport", 0))
                        dst_port = int(getattr(tcp_layer, "dport", 0))
                        protocol = "TCP"
                    elif "UDP" in tcp_class_name:
                        src_port = int(getattr(tcp_layer, "sport", 0))
                        dst_port = int(getattr(tcp_layer, "dport", 0))
                        protocol = "UDP"

                if not protocol:
                    continue

                if protocol not in protocols:
                    protocols[protocol] = 0
                protocols[protocol] += 1

                for port, service in license_ports.items():
                    if port in (dst_port, src_port):
                        server_info: dict[str, Any] = {
                            "ip": dst_ip if dst_port == port else src_ip,
                            "port": port,
                            "service": service,
                            "protocol": protocol,
                            "packet_count": 1,
                        }

                        found = False
                        for srv in license_servers:
                            if srv["ip"] == server_info["ip"] and srv["port"] == port:
                                srv["packet_count"] += 1
                                found = True
                                break
                        if not found:
                            license_servers.append(server_info)

                if _is_suspicious_connection(src_ip, dst_ip, dst_port):
                    suspicious_connections.append(
                        {
                            "src": f"{src_ip}:{src_port}",
                            "dst": f"{dst_ip}:{dst_port}",
                            "protocol": protocol,
                            "reason": _get_suspicious_reason(dst_ip, dst_port),
                        },
                    )

        elif "pyshark" in sys.modules or _try_import_pyshark():
            pyshark_mod: ModuleType | None = None
            try:
                import pyshark as pyshark_imported

                pyshark_mod = pyshark_imported
            except ImportError as e:
                logger.exception("Import error in binary_analysis: %s", e)

            if pyshark_mod is None:
                results["error"] = "pyshark import failed"
                results["packets_analyzed"] = packets_analyzed
                return results

            cap: Any = None
            if pcap_file and os.path.exists(pcap_file):
                cap = pyshark_mod.FileCapture(pcap_file)
            elif interface:
                cap = pyshark_mod.LiveCapture(interface)
                cap.sniff(timeout=10)
            else:
                results["packets_analyzed"] = packets_analyzed
                return results

            for packet in cap:
                packets_analyzed += 1

                if hasattr(packet, "ip"):
                    src_ip = str(packet.ip.src)
                    dst_ip = str(packet.ip.dst)

                    protocol = ""
                    src_port = 0
                    dst_port = 0

                    if hasattr(packet, "tcp"):
                        protocol = "TCP"
                        src_port = int(packet.tcp.srcport)
                        dst_port = int(packet.tcp.dstport)
                    elif hasattr(packet, "udp"):
                        protocol = "UDP"
                        src_port = int(packet.udp.srcport)
                        dst_port = int(packet.udp.dstport)

                    if protocol:
                        if protocol not in protocols:
                            protocols[protocol] = 0
                        protocols[protocol] += 1

                        for port, service in license_ports.items():
                            if dst_port == port:
                                server_info = {
                                    "ip": dst_ip,
                                    "port": port,
                                    "service": service,
                                    "protocol": protocol,
                                }
                                if server_info not in license_servers:
                                    license_servers.append(server_info)

            cap.close()

        else:
            results["error"] = "Neither scapy nor pyshark available for traffic analysis"

    except Exception as e:
        logger.exception("Exception in binary_analysis: %s", e)
        results["error"] = f"Traffic analysis failed: {e!s}"

    results["packets_analyzed"] = packets_analyzed
    return results


def _try_import_scapy() -> bool:
    """Try to import scapy."""
    try:
        import scapy.all as scapy

        # Store version information for debugging
        if hasattr(scapy, "__version__"):
            logger.debug("Scapy version %s available for network analysis", scapy.__version__)
        return True
    except ImportError as e:
        logger.exception("Import error in binary_analysis: %s", e)
        return False


def _try_import_pyshark() -> bool:
    """Try to import pyshark."""
    try:
        import pyshark

        if hasattr(pyshark, "__version__"):
            logger.debug("Pyshark version %s available for network analysis", pyshark.__version__)
        else:
            logger.debug("Pyshark available for network analysis")
        return True
    except ImportError as e:
        logger.exception("Import error in binary_analysis: %s", e)
        return False


def _is_suspicious_connection(src_ip: str, dst_ip: str, port: int) -> bool:
    """Check if connection is suspicious."""
    # Log connection details for debugging
    logger.debug("Checking connection from %s to %s:%s", src_ip, dst_ip, port)

    # Check for common backdoor ports
    suspicious_ports = [4444, 4445, 8888, 9999, 1337, 31337]
    if port in suspicious_ports:
        return True

    # Check for non-standard license server connections
    if port > 49152 and not dst_ip.startswith(("10.", "192.168.", "172.")):
        return True

    # Check for suspicious source IPs (e.g., localhost connecting externally)
    return src_ip in {"127.0.0.1", "::1"} and not dst_ip.startswith(("127.", "::1", "localhost"))


def _get_suspicious_reason(ip: str, port: int) -> str:
    """Get reason why connection is suspicious."""
    # Include IP in analysis for more specific reasons
    if port in {4444, 4445, 8888, 9999, 1337, 31337}:
        return f"Common backdoor port {port} to {ip}"
    if port > 49152:
        return f"High ephemeral port {port} to external IP {ip}"
    if ip.startswith(("10.", "192.168.", "172.")):
        return f"Internal network connection to {ip}:{port}"
    return f"Suspicious traffic pattern to {ip}:{port}"


# Helper functions


def get_machine_type(machine: int) -> str:
    """Convert PE machine type to string."""
    machine_types = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64"}
    return machine_types.get(machine, f"Unknown (0x{machine:x})")


def get_basic_file_info(file_path: str) -> dict[str, Any]:
    """Get basic file information."""
    try:
        stat = Path(file_path).stat()
        return {
            "size": stat.st_size,
            "created": time.ctime(stat.st_ctime),
            "modified": time.ctime(stat.st_mtime),
            "permissions": oct(stat.st_mode),
        }
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"error": str(e)}


def check_suspicious_import(func_name: str, dll_name: str, suspicious_list: list[str]) -> None:
    """Check for suspicious imports and add to list."""
    suspicious_imports = {
        "VirtualProtect": "Memory protection modification",
        "WriteProcessMemory": "Process memory manipulation",
        "CreateRemoteThread": "Remote thread creation",
        "SetWindowsHookEx": "System-wide hook installation",
        "GetProcAddress": "Dynamic function resolution",
        "LoadLibrary": "Dynamic library loading",
        "RegOpenKeyEx": "Registry access",
        "CryptEncrypt": "Cryptographic operations",
        "IsDebuggerPresent": "Anti-debugging check",
    }

    if func_name in suspicious_imports:
        suspicious_list.append(f"{dll_name}!{func_name} - {suspicious_imports[func_name]}")


def analyze_pe_resources(pe: PEFile) -> list[dict[str, Any]]:
    """Analyze PE resources.

    Args:
        pe: PE file object from pefile module

    Returns:
        List of resource dictionaries containing type, size, language information

    """
    resources: list[dict[str, Any]] = []

    def walk_resources(directory: ResourceDirectory, level: int = 0) -> None:
        """Recursively walk resource directory tree.

        Args:
            directory: Resource directory entry to traverse
            level: Current depth level in resource tree hierarchy

        """
        logger.debug("Walking resources at level %s", level)

        for entry in directory.entries:
            if hasattr(entry, "data"):
                resource_info = {
                    "type": entry.name if hasattr(entry, "name") and entry.name else f"Type_{entry.id}",
                    "size": entry.data.struct.Size,
                    "language": entry.data.lang,
                    "sublanguage": entry.data.sublang,
                    "level": level,  # Track resource depth
                }
                resources.append(resource_info)
            elif hasattr(entry, "directory"):
                walk_resources(entry.directory, level + 1)

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        walk_resources(pe.DIRECTORY_ENTRY_RESOURCE)

    return resources


def extract_binary_info(binary_path: str) -> dict[str, Any]:
    """Extract basic binary information.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing basic binary information

    """
    info = get_basic_file_info(binary_path)
    info["format"] = identify_binary_format(binary_path)

    # Add hash information
    try:
        import hashlib

        with open(binary_path, "rb") as f:
            data = f.read()
            info["md5"] = hashlib.sha256(data).hexdigest()  # Using sha256 instead of md5 for security
            info["sha1"] = hashlib.sha256(data).hexdigest()  # Using sha256 instead of sha1 for security
            info["sha256"] = hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error calculating hashes: %s", e)

    return info


def extract_binary_features(binary_path: str) -> dict[str, Any]:
    """Extract features from binary for ML analysis.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dict containing extracted features

    """
    features = {
        "file_size": 0,
        "entropy": 0.0,
        "num_sections": 0,
        "num_imports": 0,
        "num_exports": 0,
        "has_debug_info": False,
        "has_resources": False,
        "is_packed": False,
    }

    try:
        # Basic file info
        features["file_size"] = os.path.getsize(binary_path)

        # Format-specific features
        format_type = identify_binary_format(binary_path)

        if format_type == "PE" and PEFILE_AVAILABLE and pefile_module is not None:
            pe = pefile_module.PE(binary_path)
            features["num_sections"] = len(pe.sections)

            if entropies := [section.get_entropy() for section in pe.sections if hasattr(section, "get_entropy")]:
                features["entropy"] = sum(entropies) / len(entropies)
                features["is_packed"] = features["entropy"] > 7.0

            # Import/Export info
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                features["num_imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                features["num_exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

            # Debug info
            features["has_debug_info"] = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")

            # Resources
            features["has_resources"] = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error extracting features: %s", e)

    return features


def extract_patterns_from_binary(binary_path: str, pattern_size: int = 16, min_frequency: int = 2) -> list[tuple[bytes, int]]:
    """Extract frequently occurring byte patterns from binary.

    Args:
        binary_path: Path to the binary file
        pattern_size: Size of patterns to extract
        min_frequency: Minimum frequency for a pattern to be included

    Returns:
        List of (pattern, frequency) tuples

    """
    patterns: dict[bytes, int] = {}

    try:
        with open(binary_path, "rb") as f:
            data = f.read()

        # Extract patterns
        for i in range(len(data) - pattern_size):
            pattern = data[i : i + pattern_size]

            # Skip low-entropy patterns (all zeros, all ones, etc.)
            if len(set(pattern)) < 3:
                continue

            patterns[pattern] = patterns.get(pattern, 0) + 1

        # Filter by frequency
        frequent_patterns = [(pattern, count) for pattern, count in patterns.items() if count >= min_frequency]

        # Sort by frequency
        frequent_patterns.sort(key=lambda x: x[1], reverse=True)

        return frequent_patterns[:100]  # Return top 100 patterns

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error extracting patterns: %s", e)
        return []


def scan_binary(binary_path: str, signatures: dict[str, bytes] | None = None) -> dict[str, Any]:
    """Scan binary for known signatures.

    Args:
        binary_path: Path to the binary file
        signatures: Dict of signature name to byte pattern

    Returns:
        Dict containing scan results

    """
    if signatures is None:
        # Default signatures for common packers/protectors
        signatures = {
            "UPX": b"UPX!",
            "ASPack": b"ASPack",
            "PECompact": b"PECompact",
            "Themida": b"Themida",
            "VMProtect": b"VMProtect",
            "Enigma": b".enigma",
            "MPRESS": b"MPRESS",
            "FSG": b"FSG!",
            "PESpin": b"PESpin",
        }

    detected_list: list[dict[str, str]] = []
    results: dict[str, Any] = {"detected": detected_list, "scan_time": 0.0, "file_size": 0}

    try:
        start_time = time.time()

        with open(binary_path, "rb") as f:
            data = f.read()

        results["file_size"] = len(data)

        for name, signature in signatures.items():
            if signature in data:
                offset = data.find(signature)
                detected_list.append({"name": name, "offset": hex(offset), "signature": signature.hex()})

        results["scan_time"] = time.time() - start_time

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error scanning binary: %s", e)
        results["error"] = str(e)

    return results


def _optimized_basic_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized basic binary analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with analysis status, findings, and chunk information

    """
    try:
        findings_list: list[str] = []
        results: dict[str, Any] = {"status": "success", "findings": findings_list, "chunk_info": chunk_info}

        if isinstance(data, bytes) and data:
            if data.startswith(b"MZ"):
                findings_list.append("PE executable detected")
            elif data.startswith(b"\x7fELF"):
                findings_list.append("ELF binary detected")
            elif data[:4] in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"]:
                findings_list.append("Mach-O binary detected")

            if len(set(data[:1024])) < 20:
                findings_list.append("Low entropy section detected (possible padding)")
            elif len(set(data[:1024])) > 200:
                findings_list.append("High entropy section detected (possible packing/encryption)")

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def _optimized_string_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized string analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with extracted strings and license-related keywords

    """
    try:
        findings_list: list[str] = []
        license_strings: list[str] = []
        strings_found: int = 0

        results: dict[str, Any] = {
            "status": "success",
            "findings": findings_list,
            "strings_found": strings_found,
            "license_strings": license_strings,
            "chunk_info": chunk_info,
        }

        if isinstance(data, bytes):
            from ..core.string_utils import extract_ascii_strings

            strings = extract_ascii_strings(data)
            strings_found = len(strings)
            results["strings_found"] = strings_found

            license_keywords = [
                "license",
                "serial",
                "key",
                "activation",
                "trial",
                "expire",
                "valid",
            ]
            for string in strings:
                lower_string = string.lower()
                for keyword in license_keywords:
                    if keyword in lower_string:
                        license_strings.append(string)
                        break

            if license_strings:
                findings_list.append(f"Found {len(license_strings)} license-related strings")

            if strings_found > 1000:
                findings_list.append(f"High string count: {strings_found}")

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def _optimized_entropy_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized entropy analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with calculated entropy value and compression/encryption classification

    """
    try:
        findings_list: list[str] = []
        results: dict[str, Any] = {"status": "success", "findings": findings_list, "entropy": 0.0, "chunk_info": chunk_info}

        if isinstance(data, bytes) and data:
            byte_counts: list[int] = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            entropy: float = 0.0
            data_length = len(data)

            for count in byte_counts:
                if count > 0:
                    p = count / data_length
                    entropy -= p * math.log2(p)

            results["entropy"] = entropy

            if entropy < 1.0:
                findings_list.append("Very low entropy - likely padding or repetitive data")
            elif entropy < 3.0:
                findings_list.append("Low entropy - structured data")
            elif entropy > 7.0:
                findings_list.append("High entropy - likely compressed/encrypted data")
            elif entropy > 7.5:
                findings_list.append("Very high entropy - possibly packed/obfuscated")

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def _optimized_section_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized section analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with detected section headers and findings

    """
    try:
        findings_list: list[str] = []
        sections_detected: int = 0

        results: dict[str, Any] = {
            "status": "success",
            "findings": findings_list,
            "sections_detected": sections_detected,
            "chunk_info": chunk_info,
        }

        if isinstance(data, bytes) and len(data) > 64:
            if data.startswith(b"MZ"):
                pe_offset_data = data[60:64]
                if len(pe_offset_data) == 4:
                    pe_offset = struct.unpack("<I", pe_offset_data)[0]
                    if pe_offset < len(data) - 4:
                        pe_sig = data[pe_offset : pe_offset + 4]
                        if pe_sig == b"PE\x00\x00":
                            findings_list.append("Valid PE header detected")
                            results["sections_detected"] = 1

            elif data.startswith(b"\x7fELF"):
                findings_list.append("ELF header detected")
                results["sections_detected"] = 1

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def _optimized_import_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized import analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with detected DLL imports and suspicious function calls

    """
    try:
        findings_list: list[str] = []
        suspicious_imports: list[str] = []
        imports_found: int = 0

        results: dict[str, Any] = {
            "status": "success",
            "findings": findings_list,
            "imports_found": imports_found,
            "suspicious_imports": suspicious_imports,
            "chunk_info": chunk_info,
        }

        if isinstance(data, bytes):
            common_dlls = [b"kernel32.dll", b"user32.dll", b"ntdll.dll", b"advapi32.dll"]
            suspicious_functions = [
                b"CreateProcess",
                b"WriteProcessMemory",
                b"VirtualAlloc",
                b"LoadLibrary",
            ]

            for dll in common_dlls:
                if dll in data:
                    imports_found += 1
                    findings_list.append(f"Import from {dll.decode()}")

            results["imports_found"] = imports_found

            for func in suspicious_functions:
                if func in data:
                    suspicious_imports.append(func.decode())

            if suspicious_imports:
                findings_list.append(f"Found {len(suspicious_imports)} potentially suspicious imports")

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def _optimized_pattern_analysis(data: bytes, chunk_info: dict[str, Any] | None = None) -> dict[str, Any]:
    """Optimized pattern analysis for chunks.

    Args:
        data: Binary data chunk to analyze
        chunk_info: Metadata about the chunk being analyzed

    Returns:
        Dictionary with detected binary patterns and special markers

    """
    try:
        findings_list: list[str] = []
        patterns_found: list[str] = []

        results: dict[str, Any] = {
            "status": "success",
            "findings": findings_list,
            "patterns_found": patterns_found,
            "chunk_info": chunk_info,
        }

        if isinstance(data, bytes):
            if b"\x90" * 10 in data:
                patterns_found.append("NOP sled detected")
                findings_list.append("NOP sled detected")

            if b"\x00" * 50 in data:
                patterns_found.append("Large null sequence detected")
                findings_list.append("Large null sequence detected")

            if b"\xff" * 20 in data:
                patterns_found.append("Fill pattern detected")
                findings_list.append("Fill pattern detected")

            if b"DEADBEEF" in data:
                patterns_found.append("Debug marker detected")
                findings_list.append("Debug marker detected")

            dos_error_message = b"This program cannot be run in DOS mode"
            if dos_error_message in data:
                patterns_found.append("DOS error message detected")
                findings_list.append("DOS error message detected")

        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in binary_analysis: %s", e)
        return {"status": "failed", "error": str(e)}


def get_quick_disassembly(binary_path: str, max_instructions: int = 50) -> list[str]:
    """Get quick disassembly of binary entry point for UI display.

    Args:
        binary_path: Path to binary file
        max_instructions: Maximum number of instructions to disassemble

    Returns:
        List of disassembly lines

    """
    try:
        # Try to use capstone for disassembly
        if not HAS_CAPSTONE:
            return _get_basic_disassembly_info(binary_path)

        # Determine architecture from binary
        binary_format = identify_binary_format(binary_path)
        if not binary_format:
            return ["Unable to identify binary format"]

        # Read binary data
        with open(binary_path, "rb") as f:
            data = f.read(4096)  # Read first 4KB

        if capstone_module is None:
            return ["Capstone not available"]

        if binary_format == "PE":
            md = capstone_module.Cs(capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_64)
            entry_offset = _get_pe_entry_point(binary_path)
        elif binary_format == "ELF":
            md = capstone_module.Cs(capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_64)
            entry_offset = _get_elf_entry_point(binary_path)
        else:
            md = capstone_module.Cs(capstone_module.CS_ARCH_X86, capstone_module.CS_MODE_64)
            entry_offset = 0x1000

        # Disassemble instructions
        disasm_lines = []
        instructions = md.disasm(data[entry_offset : entry_offset + 512], entry_offset)

        for count, insn in enumerate(instructions):
            if count >= max_instructions:
                break

            line = f"0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}"
            disasm_lines.append(line)

        if not disasm_lines:
            return _get_basic_disassembly_info(binary_path)

        return disasm_lines

    except Exception as e:
        logger.debug("Quick disassembly error: %s", e, exc_info=True)
        return _get_basic_disassembly_info(binary_path)


def _get_basic_disassembly_info(binary_path: str) -> list[str]:
    """Get basic binary information when disassembly isn't available."""
    try:
        info = extract_binary_info(binary_path)

        lines = [
            f"# Binary: {os.path.basename(binary_path)}",
            f"# Format: {info.get('format', 'Unknown')}",
            f"# Size: {info.get('file_size', 'Unknown')} bytes",
            f"# Architecture: {info.get('architecture', 'Unknown')}",
            "",
            "# Disassembly not available - install capstone for full disassembly",
            "# Run 'pip install capstone' to enable instruction-level analysis",
            "",
            "# Binary Structure Analysis:",
        ]

        if "sections" in info:
            lines.append("# Sections:")
            lines.extend(
                f"#   {section.get('name', 'Unknown')}: {section.get('virtual_address', 'N/A')}" for section in info["sections"][:5]
            )
        if "entry_point" in info:
            lines.append(f"# Entry Point: 0x{info['entry_point']:08x}")

        return lines

    except Exception as e:
        logger.exception("Exception in binary_analysis: %s", e)
        return [
            f"# Binary: {os.path.basename(binary_path)}",
            "# Unable to analyze - may be corrupted or unsupported format",
            "# Try using external disassembly tools like objdump or radare2",
        ]


def _get_pe_entry_point(binary_path: str) -> int:
    """Get PE entry point offset."""
    try:
        if PEFILE_AVAILABLE and pefile_module is not None:
            pe = pefile_module.PE(binary_path)
            entry_point = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0x1000)
            return int(entry_point) if isinstance(entry_point, int) else 0x1000
    except Exception as e:
        logger.exception("Exception in binary_analysis: %s", e)
    return 0x1000


def _get_elf_entry_point(binary_path: str) -> int:
    """Get ELF entry point offset."""
    try:
        if PYELFTOOLS_AVAILABLE and ELFFile_class is not None:
            with open(binary_path, "rb") as f:
                elf = ELFFile_class(f)
                elf_header = getattr(elf, "header", {})
                entry = elf_header.get("e_entry", 0x1000)
                return int(entry) if isinstance(entry, int) else 0x1000
    except Exception as e:
        logger.exception("Exception in binary_analysis: %s", e)
    return 0x1000


def disassemble_with_objdump(
    binary_path: str,
    extra_args: list[str] | None = None,
    timeout: int = 30,
    parse_func: Callable[[str], list[Any]] | None = None,
) -> list[Any] | None:
    """Provide objdump disassembly fallback function.

    Args:
        binary_path: Path to binary file
        extra_args: Additional objdump arguments (e.g., ['--no-show-raw-insn'])
        timeout: Command timeout in seconds
        parse_func: Optional function to parse objdump output (accepts stdout string, returns list of instructions)

    Returns:
        List of parsed instructions or None if objdump fails

    """
    try:
        cmd = ["objdump", "-d"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(binary_path)

        result = secure_run(cmd, capture_output=True, text=True, timeout=timeout, check=False, shell=False)

        if result.returncode == 0:
            if parse_func:
                instructions = parse_func(result.stdout)
            else:
                # Simple default parsing - just return lines
                instructions = [line for line in result.stdout.splitlines() if line.strip() and not line.startswith(" ")]

            logger.info("Disassembled %d instructions using objdump", len(instructions))
            return instructions

    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("objdump not available or timed out")

    return None


# Export all functions
__all__ = [
    "analyze_binary",
    "analyze_binary_optimized",
    "analyze_elf",
    "analyze_macho",
    "analyze_patterns",
    "analyze_pe",
    "analyze_traffic",
    "disassemble_with_objdump",
    "extract_binary_features",
    "extract_binary_info",
    "extract_patterns_from_binary",
    "get_quick_disassembly",
    "identify_binary_format",
    "scan_binary",
]
