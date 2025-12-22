"""Memory Forensics Tool for LLM Integration

Provides AI models with the ability to run Volatility3 memory forensics analysis
on memory dumps to extract runtime information and security artifacts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
from typing import Any

from ...core.analysis.memory_forensics_engine import (
    get_memory_forensics_engine,
    is_volatility3_available,
)
from ...utils.logger import get_logger

logger = get_logger(__name__)


class MemoryForensicsTool:
    """LLM tool for running memory forensics analysis using Volatility3"""

    def __init__(self) -> None:
        """Initialize memory forensics tool"""
        self.engine: Any | None = get_memory_forensics_engine()
        self.analysis_cache: dict[str, dict[str, Any]] = {}

    def get_tool_definition(self) -> dict[str, Any]:
        """Get tool definition for LLM registration

        Returns:
            Tool definition dictionary

        """
        return {
            "name": "memory_forensics",
            "description": "Analyze memory dumps using Volatility3 to extract processes, modules, network connections, and security artifacts",
            "parameters": {
                "type": "object",
                "properties": {
                    "dump_path": {
                        "type": "string",
                        "description": "Path to the memory dump file to analyze",
                    },
                    "analysis_profile": {
                        "type": "string",
                        "enum": [
                            "auto",
                            "Win10x64_19041",
                            "Win11x64_22000",
                            "Win7SP1x64",
                            "LinuxGeneric",
                        ],
                        "description": "Memory analysis profile to use (default: auto)",
                        "default": "auto",
                    },
                    "deep_analysis": {
                        "type": "boolean",
                        "description": "Perform deep analysis including registry and file handles",
                        "default": True,
                    },
                    "analyze_processes": {
                        "type": "boolean",
                        "description": "Extract and analyze process information",
                        "default": True,
                    },
                    "analyze_network": {
                        "type": "boolean",
                        "description": "Extract network connection artifacts",
                        "default": True,
                    },
                    "analyze_modules": {
                        "type": "boolean",
                        "description": "Extract loaded module information",
                        "default": True,
                    },
                    "security_focus": {
                        "type": "boolean",
                        "description": "Focus on security-related artifacts and indicators",
                        "default": True,
                    },
                    "extract_strings": {
                        "type": "boolean",
                        "description": "Extract strings from memory dump",
                        "default": False,
                    },
                    "detailed_output": {
                        "type": "boolean",
                        "description": "Include detailed analysis and metadata",
                        "default": True,
                    },
                },
                "required": ["dump_path"],
            },
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute memory forensics analysis

        Args:
            **kwargs: Tool parameters

        Returns:
            Analysis results dictionary

        """
        dump_path = kwargs.get("dump_path")
        if not dump_path or not os.path.exists(dump_path):
            return {"success": False, "error": f"Memory dump not found: {dump_path}"}

        if not is_volatility3_available():
            return {"success": False, "error": "Volatility3 not available"}

        if not self.engine:
            return {"success": False, "error": "Memory forensics engine not initialized"}

        # Get parameters
        analysis_profile = kwargs.get("analysis_profile", "auto")
        deep_analysis = kwargs.get("deep_analysis", True)
        analyze_processes = kwargs.get("analyze_processes", True)
        analyze_network = kwargs.get("analyze_network", True)
        analyze_modules = kwargs.get("analyze_modules", True)
        security_focus = kwargs.get("security_focus", True)
        extract_strings = kwargs.get("extract_strings", False)
        detailed_output = kwargs.get("detailed_output", True)

        try:
            # Check cache
            cache_key = f"{dump_path}:{analysis_profile}:{deep_analysis}"
            if cache_key in self.analysis_cache:
                logger.debug(f"Returning cached memory analysis for {dump_path}")
                cached_result = self.analysis_cache[cache_key]
                cached_result["from_cache"] = True
                return cached_result

            # Convert profile string to enum
            from ...core.analysis.memory_forensics_engine import AnalysisProfile

            if analysis_profile == "LinuxGeneric":
                profile = AnalysisProfile.LINUX_GENERIC
            elif analysis_profile == "Win10x64_19041":
                profile = AnalysisProfile.WINDOWS_10
            elif analysis_profile == "Win11x64_22000":
                profile = AnalysisProfile.WINDOWS_11
            elif analysis_profile == "Win7SP1x64":
                profile = AnalysisProfile.WINDOWS_7
            else:
                profile = AnalysisProfile.AUTO_DETECT

            # Run memory forensics analysis
            analysis_result = self.engine.analyze_memory_dump(dump_path=dump_path, profile=profile, deep_analysis=deep_analysis)

            if analysis_result.error:
                return {"success": False, "error": analysis_result.error}

            # Build result for LLM consumption
            result = {
                "success": True,
                "dump_path": dump_path,
                "analysis_profile": analysis_result.analysis_profile,
                "analysis_time": analysis_result.analysis_time,
                "total_artifacts": sum(analysis_result.artifacts_found.values()),
                "artifacts_summary": analysis_result.artifacts_found,
                "has_suspicious_activity": analysis_result.has_suspicious_activity,
                "from_cache": False,
            }

            # Add process analysis if requested
            if analyze_processes and analysis_result.processes:
                result["processes"] = self._format_processes(analysis_result.processes, security_focus)
                result["process_summary"] = {
                    "total_processes": len(analysis_result.processes),
                    "hidden_processes": analysis_result.hidden_process_count,
                    "suspicious_processes": sum(bool(p.suspicious_indicators)
                                            for p in analysis_result.processes),
                }

            # Add network analysis if requested
            if analyze_network and analysis_result.network_connections:
                result["network_connections"] = self._format_network_connections(analysis_result.network_connections, security_focus)
                result["network_summary"] = {
                    "total_connections": len(analysis_result.network_connections),
                    "external_connections": len(
                        [c for c in analysis_result.network_connections if not c.remote_addr.startswith(("127.", "192.168.", "10."))]
                    ),
                }

            # Add module analysis if requested
            if analyze_modules and analysis_result.modules:
                result["modules"] = self._format_modules(analysis_result.modules, security_focus)
                result["module_summary"] = {
                    "total_modules": len(analysis_result.modules),
                    "suspicious_modules": sum(bool(m.is_suspicious)
                                          for m in analysis_result.modules),
                }

            # Add security findings
            if security_focus and analysis_result.security_findings:
                result["security_findings"] = self._format_security_findings(analysis_result.security_findings)
                result["security_assessment"] = self._assess_security_posture(analysis_result)

            # Add detailed analysis if requested
            if detailed_output:
                result["detailed_analysis"] = {
                    "registry_artifacts": len(analysis_result.registry_artifacts),
                    "file_handles": len(analysis_result.file_handles),
                    "memory_strings": len(analysis_result.memory_strings) if extract_strings else 0,
                    "analysis_summary": self.engine.get_analysis_summary(analysis_result),
                }

                # Include strings if requested
                if extract_strings and analysis_result.memory_strings:
                    result["memory_strings"] = [
                        {
                            "offset": s.offset,
                            "value": s.value[:100] if len(s.value) > 100 else s.value,
                            "encoding": s.encoding,
                            "confidence": s.confidence,
                        }
                        for s in analysis_result.memory_strings[:50]  # Limit to first 50
                    ]

            # Generate ICP supplemental data
            supplemental_data = self.engine.generate_icp_supplemental_data(analysis_result)
            result["icp_supplemental_data"] = supplemental_data

            # Cache result
            self.analysis_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"Memory forensics analysis error: {e}")
            return {"success": False, "error": str(e)}

    def _format_processes(self, processes: list[Any], security_focus: bool) -> list[dict[str, Any]]:
        """Format process information for LLM consumption"""
        formatted_processes = []

        for process in processes:
            process_data = {
                "pid": process.pid,
                "ppid": process.ppid,
                "name": process.name,
                "create_time": process.create_time,
                "session_id": process.session_id,
                "handle_count": process.handle_count,
                "thread_count": process.thread_count,
                "is_hidden": process.is_hidden,
                "wow64": process.wow64,
            }

            if command_line := getattr(process, "command_line", None):
                process_data["command_line"] = command_line

            suspicious_indicators: list[str] | None = getattr(process, "suspicious_indicators", None)
            if suspicious_indicators:
                process_data["suspicious_indicators"] = suspicious_indicators

            # Include only suspicious processes if security focused
            if not security_focus or process.is_hidden or suspicious_indicators:
                formatted_processes.append(process_data)

        return formatted_processes

    def _format_network_connections(self, connections: list[Any], security_focus: bool) -> list[dict[str, Any]]:
        """Format network connection information for LLM consumption"""
        formatted_connections = []

        for conn in connections:
            conn_data = {
                "local_addr": conn.local_addr,
                "local_port": conn.local_port,
                "remote_addr": conn.remote_addr,
                "remote_port": conn.remote_port,
                "protocol": conn.protocol,
                "state": conn.state,
                "pid": conn.pid,
            }

            if process_name := getattr(conn, "process_name", None):
                conn_data["process_name"] = process_name

            if create_time := getattr(conn, "create_time", None):
                conn_data["create_time"] = create_time

            # Include external connections or all if not security focused
            if not security_focus or not conn.remote_addr.startswith(("127.", "192.168.", "10.")):
                formatted_connections.append(conn_data)

        return formatted_connections

    def _format_modules(self, modules: list[Any], security_focus: bool) -> list[dict[str, Any]]:
        """Format module information for LLM consumption"""
        formatted_modules = []

        for module in modules:
            module_data = {
                "base_address": hex(module.base_address),
                "size": module.size,
                "name": module.name,
                "path": module.path,
                "is_suspicious": module.is_suspicious,
            }

            if version := getattr(module, "version", None):
                module_data["version"] = version

            if company := getattr(module, "company", None):
                module_data["company"] = company

            is_signed: bool | None = getattr(module, "is_signed", None)
            if is_signed is not None:
                module_data["is_signed"] = is_signed

            # Include only suspicious modules if security focused
            if not security_focus or module.is_suspicious:
                formatted_modules.append(module_data)

        return formatted_modules

    def _format_security_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Format security findings for LLM consumption"""
        return [
            {
                "type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "low"),
                "description": finding.get("description", ""),
                "count": finding.get("count", 1),
                "evidence": finding.get("modules", finding.get("evidence", [])),
            }
            for finding in findings
        ]

    def _assess_security_posture(self, analysis_result: Any) -> dict[str, Any]:
        """Assess overall security posture of the memory dump"""
        assessment = {
            "overall_risk": "low",
            "indicators_count": len(analysis_result.security_findings),
            "hidden_processes": analysis_result.hidden_process_count,
            "suspicious_modules": sum(bool(m.is_suspicious)
                                  for m in analysis_result.modules),
            "risk_factors": [],
            "recommendations": [],
        }

        risk_score = 0

        # Assess risk factors
        if analysis_result.hidden_process_count > 0:
            assessment["risk_factors"].append(f"{analysis_result.hidden_process_count} hidden processes detected")
            risk_score += 3

        suspicious_processes = sum(bool(p.suspicious_indicators)
                               for p in analysis_result.processes)
        if suspicious_processes > 0:
            assessment["risk_factors"].append(f"{suspicious_processes} suspicious processes detected")
            risk_score += 2

        suspicious_modules = sum(bool(m.is_suspicious)
                             for m in analysis_result.modules)
        if suspicious_modules > 0:
            assessment["risk_factors"].append(f"{suspicious_modules} suspicious modules detected")
            risk_score += 2

        external_connections = len(
            [c for c in analysis_result.network_connections if not c.remote_addr.startswith(("127.", "192.168.", "10."))]
        )
        if external_connections > 10:
            assessment["risk_factors"].append(f"{external_connections} external network connections")
            risk_score += 1

        # Determine overall risk
        if risk_score >= 6:
            assessment["overall_risk"] = "critical"
        elif risk_score >= 4:
            assessment["overall_risk"] = "high"
        elif risk_score >= 2:
            assessment["overall_risk"] = "medium"

        # Generate recommendations
        if analysis_result.hidden_process_count > 0:
            assessment["recommendations"].append("Investigate hidden processes for potential rootkit activity")

        if suspicious_processes > 0:
            assessment["recommendations"].append("Analyze suspicious processes for malware indicators")

        if external_connections > 5:
            assessment["recommendations"].append("Review external network connections for data exfiltration")

        return assessment

    def analyze_specific_process(self, dump_path: str, process_id: int) -> dict[str, Any]:
        """Analyze a specific process from memory dump

        Args:
            dump_path: Path to memory dump
            process_id: Process ID to analyze

        Returns:
            Process-specific analysis results

        """
        try:
            if not is_volatility3_available() or not self.engine:
                return {"success": False, "error": "Memory forensics engine not available"}

            process_analysis: dict[str, Any] | None = self.engine.analyze_process_memory(process_id, dump_path)

            if process_analysis is None:
                return {"success": False, "error": f"Failed to analyze process {process_id}"}

            return {
                "success": True,
                "process_id": process_id,
                "dump_path": dump_path,
                "analysis_result": process_analysis,
            }

        except Exception as e:
            logger.error(f"Process-specific analysis error: {e}")
            return {"success": False, "error": str(e)}


def create_memory_forensics_tool() -> MemoryForensicsTool:
    """Factory function to create memory forensics tool"""
    return MemoryForensicsTool()
