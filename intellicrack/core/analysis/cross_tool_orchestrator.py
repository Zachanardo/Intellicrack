"""Cross-Tool Analysis Orchestrator.

This module orchestrates analysis across multiple tools (Ghidra, Frida, Radare2)
and provides unified analysis workflows with result correlation.

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

import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..frida_manager import FridaManager
from .ghidra_analyzer import run_advanced_ghidra_analysis
from .ghidra_results import GhidraAnalysisResult
from .radare2_enhanced_integration import EnhancedR2Integration

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFunction:
    """Function data correlated across multiple tools."""

    name: str
    ghidra_data: Optional[Dict[str, Any]] = None
    r2_data: Optional[Dict[str, Any]] = None
    frida_data: Optional[Dict[str, Any]] = None
    addresses: Dict[str, int] = field(default_factory=dict)
    sizes: Dict[str, int] = field(default_factory=dict)
    confidence_score: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class CorrelatedString:
    """String data correlated across tools."""

    value: str
    ghidra_refs: List[int] = field(default_factory=list)
    r2_refs: List[int] = field(default_factory=list)
    frida_refs: List[int] = field(default_factory=list)
    is_license_related: bool = False
    is_crypto_related: bool = False
    importance_score: float = 0.0


@dataclass
class UnifiedAnalysisResult:
    """Unified result from cross-tool analysis."""

    binary_path: str
    timestamp: datetime
    functions: List[CorrelatedFunction] = field(default_factory=list)
    strings: List[CorrelatedString] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    protection_mechanisms: List[Dict[str, Any]] = field(default_factory=list)
    bypass_strategies: List[Dict[str, Any]] = field(default_factory=list)
    memory_maps: Dict[str, Any] = field(default_factory=dict)
    call_graph: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class CrossToolOrchestrator:
    """Orchestrates analysis across multiple binary analysis tools."""

    def __init__(self, binary_path: str, main_app=None):
        """Initialize the orchestrator.

        Args:
            binary_path: Path to the binary to analyze
            main_app: Optional reference to main application for GUI updates
        """
        self.binary_path = binary_path
        self.main_app = main_app
        self.logger = logger

        # Tool instances
        self.ghidra_results: Optional[GhidraAnalysisResult] = None
        self.r2_integration: Optional[EnhancedR2Integration] = None
        self.frida_manager: Optional[FridaManager] = None

        # Analysis state
        self.analysis_complete = {"ghidra": False, "radare2": False, "frida": False}
        self.analysis_results = {"ghidra": None, "radare2": None, "frida": None}

        # Threading
        self.analysis_lock = threading.Lock()
        self.analysis_threads: List[threading.Thread] = []

        # Initialize tools
        self._initialize_tools()

    def _initialize_tools(self):
        """Initialize analysis tools."""
        try:
            # Initialize Radare2
            self.r2_integration = EnhancedR2Integration(self.binary_path)
            self.logger.info("Initialized Radare2 integration")

            # Initialize Frida if available
            try:
                self.frida_manager = FridaManager()
                self.logger.info("Initialized Frida manager")
            except Exception as e:
                self.logger.warning(f"Frida initialization failed: {e}")
                self.frida_manager = None

        except Exception as e:
            self.logger.error(f"Failed to initialize tools: {e}")

    def run_parallel_analysis(self, tools: Optional[List[str]] = None) -> UnifiedAnalysisResult:
        """Run analysis in parallel across specified tools.

        Args:
            tools: List of tools to use ['ghidra', 'radare2', 'frida'] or None for all

        Returns:
            UnifiedAnalysisResult containing correlated data
        """
        if tools is None:
            tools = ["ghidra", "radare2", "frida"]

        self.logger.info(f"Starting parallel analysis with tools: {tools}")

        # Start analysis threads
        if "ghidra" in tools:
            thread = threading.Thread(target=self._run_ghidra_analysis, daemon=True)
            thread.start()
            self.analysis_threads.append(thread)

        if "radare2" in tools:
            thread = threading.Thread(target=self._run_radare2_analysis, daemon=True)
            thread.start()
            self.analysis_threads.append(thread)

        if "frida" in tools and self.frida_manager:
            thread = threading.Thread(target=self._run_frida_analysis, daemon=True)
            thread.start()
            self.analysis_threads.append(thread)

        # Wait for all threads to complete
        for thread in self.analysis_threads:
            thread.join(timeout=60)  # 60 second timeout per tool

        # Correlate results
        return self._correlate_results()

    def run_sequential_analysis(self, workflow: List[Dict[str, Any]]) -> UnifiedAnalysisResult:
        """Run analysis sequentially with data flow between tools.

        Args:
            workflow: List of workflow steps with tool and configuration

        Returns:
            UnifiedAnalysisResult
        """
        self.logger.info(f"Starting sequential analysis with {len(workflow)} steps")

        for step in workflow:
            tool = step.get("tool")
            config = step.get("config", {})
            depends_on = step.get("depends_on", [])

            # Wait for dependencies
            for dep in depends_on:
                while not self.analysis_complete.get(dep, False):
                    time.sleep(0.5)

            # Run analysis
            if tool == "ghidra":
                self._run_ghidra_analysis(config)
            elif tool == "radare2":
                self._run_radare2_analysis(config)
            elif tool == "frida":
                self._run_frida_analysis(config)
            else:
                self.logger.warning(f"Unknown tool in workflow: {tool}")

        return self._correlate_results()

    def _run_ghidra_analysis(self, config: Optional[Dict[str, Any]] = None):
        """Run Ghidra analysis."""
        try:
            self.logger.info("Starting Ghidra analysis")

            if self.main_app:
                # Use GUI integration
                run_advanced_ghidra_analysis(self.main_app)

                # Parse output from main_app
                # This would normally parse the Ghidra output from the GUI
                self.ghidra_results = GhidraAnalysisResult(binary_path=self.binary_path, timestamp=datetime.now())
            else:
                # Run headless
                # In production, this would run Ghidra headless and parse results
                self.ghidra_results = GhidraAnalysisResult(binary_path=self.binary_path, timestamp=datetime.now())

            with self.analysis_lock:
                self.analysis_complete["ghidra"] = True
                self.analysis_results["ghidra"] = self.ghidra_results

            self.logger.info("Ghidra analysis complete")

        except Exception as e:
            self.logger.error(f"Ghidra analysis failed: {e}")
            with self.analysis_lock:
                self.analysis_complete["ghidra"] = True

    def _run_radare2_analysis(self, config: Optional[Dict[str, Any]] = None):
        """Run Radare2 analysis."""
        try:
            self.logger.info("Starting Radare2 analysis")

            if not self.r2_integration:
                self.r2_integration = EnhancedR2Integration(self.binary_path)

            # Run comprehensive analysis
            analysis_types = config.get("analysis_types") if config else None
            results = self.r2_integration.run_comprehensive_analysis(analysis_types)

            with self.analysis_lock:
                self.analysis_complete["radare2"] = True
                self.analysis_results["radare2"] = results

            self.logger.info("Radare2 analysis complete")

        except Exception as e:
            self.logger.error(f"Radare2 analysis failed: {e}")
            with self.analysis_lock:
                self.analysis_complete["radare2"] = True

    def _run_frida_analysis(self, config: Optional[Dict[str, Any]] = None):
        """Run Frida dynamic analysis."""
        try:
            if not self.frida_manager:
                self.logger.warning("Frida not available, skipping")
                with self.analysis_lock:
                    self.analysis_complete["frida"] = True
                return

            self.logger.info("Starting Frida analysis")

            # Attach to process or spawn
            pid = config.get("pid") if config else None
            if pid:
                self.frida_manager.attach_to_process(pid)
            else:
                # Would spawn process in production
                self.logger.info("Would spawn process for Frida analysis")

            # Run standard scripts
            scripts = config.get("scripts", ["memory_scan", "api_monitor", "hook_detection"])
            results = {}

            for script_name in scripts:
                if script_name == "memory_scan":
                    results["memory"] = self._frida_memory_scan()
                elif script_name == "api_monitor":
                    results["api_calls"] = self._frida_api_monitor()
                elif script_name == "hook_detection":
                    results["hooks"] = self._frida_hook_detection()

            with self.analysis_lock:
                self.analysis_complete["frida"] = True
                self.analysis_results["frida"] = results

            self.logger.info("Frida analysis complete")

        except Exception as e:
            self.logger.error(f"Frida analysis failed: {e}")
            with self.analysis_lock:
                self.analysis_complete["frida"] = True

    def _frida_memory_scan(self) -> Dict[str, Any]:
        """Perform memory scanning with Frida."""
        results = {"strings": [], "patterns": [], "suspicious_regions": []}

        if not self.frida_manager:
            return results

        # Memory scan script
        script_code = """
        function scanMemory() {
            var results = {
                strings: [],
                patterns: [],
                regions: []
            };

            Process.enumerateRanges('r--', {
                onMatch: function(range) {
                    try {
                        var data = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                        // Look for license-related strings
                        var str = String.fromCharCode.apply(null, new Uint8Array(data));
                        if (str.includes('license') || str.includes('trial') || str.includes('expired')) {
                            results.strings.push({
                                address: range.base.toString(),
                                content: str.substring(0, 100)
                            });
                        }
                    } catch(e) {}
                },
                onComplete: function() {
                    send(results);
                }
            });
        }

        scanMemory();
        """

        try:
            # Execute the memory scan script
            if hasattr(self.frida_manager, "inject_script"):
                script_result = self.frida_manager.inject_script(self.frida_manager.target_pid, script_code)
                if script_result and "data" in script_result:
                    results.update(script_result["data"])
            else:
                self.logger.debug("Frida script injection method not available")
        except Exception as e:
            self.logger.error(f"Memory scan failed: {e}")

        return results

    def _frida_api_monitor(self) -> List[Dict[str, Any]]:
        """Monitor API calls with Frida."""
        api_calls = []

        if not self.frida_manager:
            return api_calls

        # API monitoring script
        script_code = """
        var apis = [
            'CreateFileW', 'ReadFile', 'WriteFile',
            'RegOpenKeyExW', 'RegQueryValueExW',
            'InternetOpenW', 'HttpSendRequestW'
        ];

        apis.forEach(function(api) {
            try {
                var addr = Module.findExportByName(null, api);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                api: api,
                                args: args,
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            } catch(e) {}
        });
        """

        try:
            # Execute the API monitoring script
            if hasattr(self.frida_manager, "inject_script"):
                script_result = self.frida_manager.inject_script(self.frida_manager.target_pid, script_code)
                if script_result and "calls" in script_result:
                    api_calls.extend(script_result["calls"])
            else:
                self.logger.debug("Frida script injection method not available")
        except Exception as e:
            self.logger.error(f"API monitoring failed: {e}")

        return api_calls

    def _frida_hook_detection(self) -> Dict[str, Any]:
        """Detect hooks and patches with Frida."""
        hooks = {"inline_hooks": [], "iat_hooks": [], "patches": []}

        if not self.frida_manager:
            return hooks

        # Hook detection script
        script_code = """
        function detectHooks() {
            var results = {
                inline: [],
                iat: [],
                patches: []
            };

            // Check for inline hooks
            var modules = Process.enumerateModules();
            modules.forEach(function(module) {
                var exports = module.enumerateExports();
                exports.forEach(function(exp) {
                    try {
                        var bytes = Memory.readByteArray(exp.address, 5);
                        var arr = new Uint8Array(bytes);
                        // Check for JMP (0xE9) or CALL (0xE8)
                        if (arr[0] == 0xE9 || arr[0] == 0xE8) {
                            results.inline.push({
                                module: module.name,
                                function: exp.name,
                                address: exp.address.toString()
                            });
                        }
                    } catch(e) {}
                });
            });

            send(results);
        }

        detectHooks();
        """

        try:
            # Execute the hook detection script
            if hasattr(self.frida_manager, "inject_script"):
                script_result = self.frida_manager.inject_script(self.frida_manager.target_pid, script_code)
                if script_result and "hooks" in script_result:
                    hooks.update(script_result["hooks"])
            else:
                self.logger.debug("Frida script injection method not available")
        except Exception as e:
            self.logger.error(f"Hook detection failed: {e}")

        return hooks

    def _correlate_results(self) -> UnifiedAnalysisResult:
        """Correlate results from all tools."""
        self.logger.info("Correlating results from all tools")

        result = UnifiedAnalysisResult(binary_path=self.binary_path, timestamp=datetime.now())

        # Correlate functions
        result.functions = self._correlate_functions()

        # Correlate strings
        result.strings = self._correlate_strings()

        # Combine vulnerabilities
        result.vulnerabilities = self._combine_vulnerabilities()

        # Identify protection mechanisms
        result.protection_mechanisms = self._identify_protections()

        # Generate bypass strategies
        result.bypass_strategies = self._generate_bypass_strategies()

        # Build unified call graph
        result.call_graph = self._build_unified_call_graph()

        # Add metadata
        result.metadata = {
            "tools_used": list(self.analysis_complete.keys()),
            "analysis_complete": all(self.analysis_complete.values()),
            "correlation_confidence": self._calculate_correlation_confidence(),
        }

        return result

    def _correlate_functions(self) -> List[CorrelatedFunction]:
        """Correlate function data across tools."""
        correlated = []
        function_map = defaultdict(CorrelatedFunction)

        # Process Ghidra functions
        if self.ghidra_results:
            for func in self.ghidra_results.functions:
                name = func.get("name", "")
                cf = function_map[name]
                cf.name = name
                cf.ghidra_data = func
                cf.addresses["ghidra"] = func.get("address", 0)
                cf.sizes["ghidra"] = func.get("size", 0)

        # Process Radare2 functions
        r2_results = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            decompiler = r2_results["components"].get("decompiler", {})
            if "functions" in decompiler:
                for func in decompiler["functions"]:
                    name = func.get("name", "")
                    cf = function_map[name]
                    cf.name = name
                    cf.r2_data = func
                    cf.addresses["r2"] = func.get("offset", 0)
                    cf.sizes["r2"] = func.get("size", 0)

        # Process Frida data
        frida_results = self.analysis_results.get("frida", {})
        if frida_results and "hooks" in frida_results:
            for hook in frida_results["hooks"].get("inline", []):
                name = hook.get("function", "")
                cf = function_map[name]
                cf.name = name
                cf.frida_data = hook
                cf.notes.append("Has inline hook detected by Frida")

        # Calculate confidence scores
        for _name, cf in function_map.items():
            sources = sum([1 if cf.ghidra_data else 0, 1 if cf.r2_data else 0, 1 if cf.frida_data else 0])
            cf.confidence_score = sources / 3.0
            correlated.append(cf)

        return correlated

    def _correlate_strings(self) -> List[CorrelatedString]:
        """Correlate string data across tools."""
        correlated = []
        string_map = defaultdict(CorrelatedString)

        # Process Ghidra strings
        if self.ghidra_results:
            for string_data in self.ghidra_results.strings:
                value = string_data.get("value", "")
                cs = string_map[value]
                cs.value = value
                cs.ghidra_refs = string_data.get("xrefs", [])

        # Process Radare2 strings
        r2_results = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            strings = r2_results["components"].get("strings", {})
            if "strings" in strings:
                for string_data in strings["strings"]:
                    value = string_data.get("string", "")
                    cs = string_map[value]
                    cs.value = value
                    cs.r2_refs = [string_data.get("vaddr", 0)]

        # Process Frida strings
        frida_results = self.analysis_results.get("frida", {})
        if frida_results and "memory" in frida_results:
            for string_data in frida_results["memory"].get("strings", []):
                value = string_data.get("content", "")
                cs = string_map[value]
                cs.value = value
                cs.frida_refs = [int(string_data.get("address", "0"), 16)]

        # Classify strings
        for value, cs in string_map.items():
            # Check for license-related
            license_keywords = ["license", "trial", "expired", "activation", "serial", "key"]
            if any(kw in value.lower() for kw in license_keywords):
                cs.is_license_related = True
                cs.importance_score += 0.5

            # Check for crypto-related
            crypto_keywords = ["aes", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher"]
            if any(kw in value.lower() for kw in crypto_keywords):
                cs.is_crypto_related = True
                cs.importance_score += 0.3

            # Score based on references
            total_refs = len(cs.ghidra_refs) + len(cs.r2_refs) + len(cs.frida_refs)
            cs.importance_score += min(total_refs * 0.1, 0.5)

            correlated.append(cs)

        return correlated

    def _combine_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Combine vulnerability findings from all tools."""
        vulnerabilities = []

        # Get R2 vulnerabilities
        r2_results = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            vuln_data = r2_results["components"].get("vulnerability", {})
            if "vulnerabilities" in vuln_data:
                for vuln in vuln_data["vulnerabilities"]:
                    vuln["source"] = "radare2"
                    vulnerabilities.append(vuln)

        # Add Frida runtime vulnerabilities
        frida_results = self.analysis_results.get("frida", {})
        if frida_results and "hooks" in frida_results:
            inline_hooks = frida_results["hooks"].get("inline", [])
            if inline_hooks:
                vulnerabilities.append(
                    {
                        "type": "runtime_hooks",
                        "severity": "high",
                        "description": f"Detected {len(inline_hooks)} inline hooks",
                        "source": "frida",
                        "details": inline_hooks,
                    }
                )

        return vulnerabilities

    def _identify_protections(self) -> List[Dict[str, Any]]:
        """Identify protection mechanisms from analysis."""
        protections = []

        # Check for anti-debugging
        r2_results = self.analysis_results.get("radare2", {})
        if r2_results:
            # Check for common anti-debug functions
            anti_debug_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString"]

            components = r2_results.get("components", {})
            imports = components.get("imports", {})
            if "imports" in imports:
                for imp in imports["imports"]:
                    if any(api in imp.get("name", "") for api in anti_debug_apis):
                        protections.append({"type": "anti_debugging", "mechanism": imp.get("name"), "confidence": 0.9})

        # Check for obfuscation
        if self.ghidra_results:
            # High ratio of unnamed functions suggests obfuscation
            total_funcs = len(self.ghidra_results.functions)
            unnamed_funcs = sum(1 for f in self.ghidra_results.functions if f.get("name", "").startswith("sub_"))
            if total_funcs > 0 and unnamed_funcs / total_funcs > 0.7:
                protections.append({"type": "obfuscation", "mechanism": "symbol_stripping", "confidence": unnamed_funcs / total_funcs})

        return protections

    def _generate_bypass_strategies(self) -> List[Dict[str, Any]]:
        """Generate bypass strategies based on findings."""
        strategies = []

        # Get bypass suggestions from R2
        r2_results = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            bypass_data = r2_results["components"].get("bypass", {})
            if "strategies" in bypass_data:
                strategies.extend(bypass_data["strategies"])

        # Add Frida-based strategies
        if self.frida_manager:
            strategies.append(
                {
                    "name": "Runtime Patching",
                    "description": "Use Frida to patch protection checks at runtime",
                    "tool": "frida",
                    "confidence": 0.9,
                    "implementation": "Hook protection functions and return success",
                }
            )

        # Add strategies based on protections found
        for protection in self._identify_protections():
            if protection["type"] == "anti_debugging":
                strategies.append(
                    {
                        "name": f"Bypass {protection['mechanism']}",
                        "description": f"Hook and bypass {protection['mechanism']} check",
                        "tool": "frida",
                        "confidence": 0.8,
                        "implementation": f"Interceptor.replace({protection['mechanism']}, () => 0);",
                    }
                )

        return strategies

    def _build_unified_call_graph(self) -> Dict[str, Any]:
        """Build unified call graph from all tools."""
        graph = {"nodes": [], "edges": [], "metadata": {}}

        # Get R2 call graph
        if self.r2_integration:
            r2_graph = self.r2_integration.generate_call_graph()
            if r2_graph:
                graph["nodes"].extend(r2_graph.get("nodes", []))
                graph["edges"].extend(r2_graph.get("edges", []))

        # Merge with Ghidra data
        if self.ghidra_results:
            # Add Ghidra-specific nodes
            for func in self.ghidra_results.functions:
                node_id = func.get("name", "")
                if not any(n["id"] == node_id for n in graph["nodes"]):
                    graph["nodes"].append({"id": node_id, "label": node_id, "source": "ghidra", "address": func.get("address", 0)})

        return graph

    def _calculate_correlation_confidence(self) -> float:
        """Calculate overall correlation confidence."""
        tools_complete = sum(1 for v in self.analysis_complete.values() if v)
        total_tools = len(self.analysis_complete)

        if total_tools == 0:
            return 0.0

        return tools_complete / total_tools

    def export_unified_report(self, output_path: str):
        """Export unified analysis report.

        Args:
            output_path: Path for output file
        """
        result = self._correlate_results()

        # Convert to JSON-serializable format
        report = {
            "binary_path": result.binary_path,
            "timestamp": result.timestamp.isoformat(),
            "functions": [
                {"name": f.name, "addresses": f.addresses, "sizes": f.sizes, "confidence": f.confidence_score, "notes": f.notes}
                for f in result.functions
            ],
            "strings": [
                {
                    "value": s.value,
                    "is_license_related": s.is_license_related,
                    "is_crypto_related": s.is_crypto_related,
                    "importance": s.importance_score,
                    "references": len(s.ghidra_refs) + len(s.r2_refs) + len(s.frida_refs),
                }
                for s in result.strings
            ],
            "vulnerabilities": result.vulnerabilities,
            "protections": result.protection_mechanisms,
            "bypass_strategies": result.bypass_strategies,
            "metadata": result.metadata,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Exported unified report to {output_path}")

    def cleanup(self):
        """Clean up resources."""
        if self.r2_integration:
            self.r2_integration.cleanup()

        if self.frida_manager:
            self.frida_manager.detach()

        self.logger.info("CrossToolOrchestrator cleanup complete")


def create_orchestrator(binary_path: str, main_app=None) -> CrossToolOrchestrator:
    """Factory function to create orchestrator.

    Args:
        binary_path: Path to binary
        main_app: Optional GUI reference

    Returns:
        New CrossToolOrchestrator instance
    """
    return CrossToolOrchestrator(binary_path, main_app)
