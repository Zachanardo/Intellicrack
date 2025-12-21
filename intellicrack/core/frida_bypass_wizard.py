"""Frida bypass wizard for Intellicrack core functionality.

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

import asyncio
import logging
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any

from .frida_constants import ProtectionType
from .frida_presets import WIZARD_CONFIGS, get_preset_by_software, get_scripts_for_protection


"""
Automated Bypass Wizard for Frida Operations

This module implements an intelligent wizard system that automatically:
- Detects protection mechanisms
- Selects appropriate bypass strategies
- Applies bypasses in optimal order
- Monitors success and adapts as needed
"""

logger = logging.getLogger(__name__)


class WizardState(Enum):
    """Wizard execution states.

    Represents the different stages of the bypass wizard workflow.
    The wizard progresses through these states sequentially:
    IDLE -> ANALYZING -> DETECTING -> PLANNING -> APPLYING -> MONITORING -> COMPLETE

    Can transition to FAILED from any state if an error occurs.
    """

    IDLE = "idle"
    ANALYZING = "analyzing"
    DETECTING = "detecting"
    PLANNING = "planning"
    APPLYING = "applying"
    MONITORING = "monitoring"
    COMPLETE = "complete"
    FAILED = "failed"


class BypassStrategy:
    """Represents a bypass strategy for a specific protection."""

    def __init__(
        self,
        protection_type: ProtectionType,
        scripts: list[str],
        priority: int = 50,
        dependencies: list[ProtectionType] | None = None,
    ) -> None:
        """Initialize a bypass strategy.

        Args:
            protection_type: The type of protection this strategy bypasses.
            scripts: List of Frida script paths to apply.
            priority: Execution priority (higher = earlier execution).
            dependencies: Other protections that must be bypassed first.

        Attributes:
            success_indicators (list): Patterns indicating successful bypass.
            failure_indicators (list): Patterns indicating bypass failure.
            applied (bool): Whether this strategy has been applied.
            success (bool or None): Success status (True/False/None).

        """
        self.protection_type = protection_type
        self.scripts = scripts
        self.priority = priority
        self.dependencies = dependencies or []
        self.success_indicators: list[dict[str, Any]] = []
        self.failure_indicators: list[dict[str, Any]] = []
        self.applied = False
        self.success: bool | None = None

    def add_success_indicator(self, indicator: dict[str, Any]) -> None:
        """Add an indicator of successful bypass.

        Args:
            indicator: Dictionary containing pattern/condition that indicates
                      the bypass was successful (e.g., specific log messages,
                      function return values, etc.).

        """
        self.success_indicators.append(indicator)

    def add_failure_indicator(self, indicator: dict[str, Any]) -> None:
        """Add an indicator of failed bypass.

        Args:
            indicator: Dictionary containing pattern/condition that indicates
                      the bypass failed (e.g., error messages, exceptions,
                      protection still active, etc.).

        """
        self.failure_indicators.append(indicator)

    def can_apply(self, completed_protections: set[ProtectionType]) -> bool:
        """Check if strategy can be applied based on dependencies.

        A strategy can only be applied if all its dependencies have been
        successfully bypassed first.

        Args:
            completed_protections: Set of protections already bypassed.

        Returns:
            bool: True if all dependencies are satisfied.

        Example:
            If LICENSE bypass depends on ANTI_DEBUG, it can only run
            after ANTI_DEBUG has been successfully bypassed.

        """
        return all(dep in completed_protections for dep in self.dependencies)

    def __repr__(self) -> str:
        """Return string representation of the bypass strategy."""
        return f"BypassStrategy({self.protection_type.value}, scripts={self.scripts})"


class FridaBypassWizard:
    """Automated bypass wizard with intelligent decision making."""

    def __init__(self, frida_manager: object) -> None:
        """Initialize the Frida bypass wizard.

        Args:
            frida_manager: Instance of FridaManager for script execution

        Attributes:
            state (str): Current wizard state
            session_id (str): Active Frida session ID
            target_process (dict): Target process information
            config (dict): Active wizard configuration
            mode (str): Operating mode (safe/balanced/aggressive/stealth/analysis)
            detected_protections (dict): Map of detected protection types
            strategies (list): List of planned bypass strategies
            metrics (dict): Performance and success metrics

        """
        self.frida_manager = frida_manager
        self.state = WizardState.IDLE
        self.session_id: str | None = None
        self.target_process: dict[str, Any] | None = None

        # Wizard configuration
        self.config: dict[str, Any] = WIZARD_CONFIGS["balanced"]
        self.mode = "balanced"

        # Detection results
        self.detected_protections: dict[ProtectionType, bool] = {}
        self.protection_evidence: dict[ProtectionType, list[str]] = {}

        # Bypass strategies
        self.strategies: list[BypassStrategy] = []
        self.applied_strategies: list[BypassStrategy] = []
        self.successful_bypasses: set[ProtectionType] = set()
        self.failed_bypasses: set[ProtectionType] = set()
        self.executed_bypasses: set[ProtectionType] = set()

        # Progress tracking
        self.progress = 0
        self.progress_callback: Callable[[int], None] | None = None
        self.status_callback: Callable[[str], None] | None = None

        # Analysis results
        self.analysis_results: dict[str, Any] = {
            "process_info": {},
            "modules": [],
            "imports": [],
            "strings": [],
            "patterns": [],
        }

        # Success metrics
        self.metrics: dict[str, int | float | None] = {
            "start_time": None,
            "end_time": None,
            "protections_detected": 0,
            "bypasses_attempted": 0,
            "bypasses_successful": 0,
            "scripts_loaded": 0,
            "hooks_installed": 0,
            "retry_successes": 0,
            "retry_failures": 0,
        }

    def set_mode(self, mode: str) -> None:
        """Set wizard mode (safe, balanced, aggressive, stealth, analysis).

        Different modes optimize for different scenarios:
        - safe: Minimal risk, basic bypasses only
        - balanced: Good mix of effectiveness and safety
        - aggressive: Maximum bypass attempts, higher detection risk
        - stealth: Focuses on avoiding detection
        - analysis: Information gathering only, no bypasses

        Args:
            mode: Operating mode name

        Side Effects:
            Updates self.mode and self.config with mode-specific settings

        """
        if mode in WIZARD_CONFIGS:
            self.mode = mode
            self.config = WIZARD_CONFIGS[mode]
            logger.info("Wizard mode set to: %s", mode)
        else:
            logger.warning("Unknown mode: %s, using balanced", mode)

    def set_callbacks(
        self,
        progress_callback: Callable[[int], None] | None = None,
        status_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Set callback functions for progress and status updates.

        Args:
            progress_callback: Function called with progress percentage (0-100).
            status_callback: Function called with status message strings.

        Example:
            wizard.set_callbacks(
                progress_callback=lambda p: print(f"Progress: {p}%"),
                status_callback=lambda s: print(f"Status: {s}")
            )

        """
        self.progress_callback = progress_callback
        self.status_callback = status_callback

    def _update_progress(self, progress: int, message: str = "") -> None:
        """Update progress and notify callbacks."""
        self.progress = progress
        if self.progress_callback:
            self.progress_callback(progress)
        if self.status_callback and message:
            self.status_callback(message)
        logger.info("Wizard progress: %s%% - %s", progress, message)

    def _update_state(self, state: WizardState) -> None:
        """Update wizard state."""
        self.state = state
        logger.debug("Wizard state changed to: %s", state.value)

    async def run(self, session_id: str, target_info: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run the automated bypass wizard.

        Executes the complete bypass workflow:
        1. Analyze target process
        2. Detect protection mechanisms
        3. Plan bypass strategy
        4. Apply bypasses in optimal order
        5. Monitor and verify results

        Args:
            session_id: Frida session ID for the target process
            target_info: Optional dictionary with process information:
                        {name, pid, path}

        Returns:
            Dict containing comprehensive report with:
            - success: Overall success status
            - detections: Found protections
            - bypasses: Applied bypasses and results
            - metrics: Performance statistics

        Raises:
            Exception: If wizard fails at any stage

        Complexity:
            Time: O(n*m) where n is protections, m is scripts per protection
            Space: O(n) for storing strategies and results

        """
        try:
            self.session_id = session_id
            self.target_process = target_info
            self.metrics["start_time"] = float(time.time())

            # Step 1: Analyze target process
            self._update_state(WizardState.ANALYZING)
            self._update_progress(10, "Analyzing target process...")
            await self._analyze_process()

            # Step 2: Detect protections
            self._update_state(WizardState.DETECTING)
            self._update_progress(25, "Detecting protection mechanisms...")
            await self._detect_protections()

            # Step 3: Plan bypass strategy
            self._update_state(WizardState.PLANNING)
            self._update_progress(40, "Planning bypass strategy...")
            await self._plan_strategy()

            # Step 4: Apply bypasses
            self._update_state(WizardState.APPLYING)
            self._update_progress(60, "Applying bypass techniques...")
            await self._apply_bypasses()

            # Step 5: Monitor and verify
            self._update_state(WizardState.MONITORING)
            self._update_progress(85, "Monitoring and verifying bypasses...")
            await self._monitor_results()

            # Complete
            self._update_state(WizardState.COMPLETE)
            self._update_progress(100, "Wizard completed successfully!")

            self.metrics["end_time"] = float(time.time())

            return self._generate_report()

        except Exception as e:
            self._update_state(WizardState.FAILED)
            self._update_progress(self.progress, f"Wizard failed: {e}")
            logger.exception("Bypass wizard failed: %s", e)
            raise

    async def _analyze_process(self) -> None:
        """Analyze the target process.

        Performs initial reconnaissance on the target:
        - Enumerates loaded modules
        - Collects imports and exports
        - Searches for protection-related strings
        - Identifies protection APIs

        Results are stored in self.analysis_results for use in
        detection and planning phases.

        Side Effects:
            - Creates and loads temporary analysis script
            - Updates analysis_results dictionary
            - Updates progress to 20%

        """
        try:
            # Basic process analysis
            if self.target_process:
                self.analysis_results["process_info"] = {
                    "name": self.target_process.get("name", "Unknown"),
                    "pid": self.target_process.get("pid", 0),
                    "path": self.target_process.get("path", ""),
                }

            # Load analysis script
            analysis_script = self._create_analysis_script()

            # Create temporary analysis script
            temp_script = Path("temp_analysis.js")
            await asyncio.to_thread(lambda: temp_script.write_text(analysis_script, encoding="utf-8"))

            if hasattr(self.frida_manager, "load_script"):
                if success := self.frida_manager.load_script(
                    self.session_id,
                    str(temp_script),
                    {"analysis_mode": True},
                ):
                    logger.info("Analysis script loaded successfully: %s", success)
                    await asyncio.sleep(2)
                else:
                    logger.warning("Failed to load analysis script")

            # Clean up
            temp_script.unlink()

            self._update_progress(20, "Process analysis complete")

        except Exception as e:
            logger.exception("Process analysis failed: %s", e)

    def _create_analysis_script(self) -> str:
        """Create Frida script for process analysis.

        Generates a comprehensive analysis script that:
        - Enumerates all loaded modules with metadata
        - Collects imported functions from main module
        - Searches memory for protection-related strings
        - Detects common protection API usage

        Returns:
            str: JavaScript code for Frida analysis

        The script sends results via Frida's send() API with:
        - type: 'analysis'
        - category: 'modules'/'imports'/'strings'/'protection_apis'
        - data: Collected information

        """
        return """
        // Process Analysis Script
        const modules = Process.enumerateModules();
        const imports = [];
        const strings = [];

        // Enumerate modules
        send({
            type: 'analysis',
            category: 'modules',
            data: modules.map(m => ({
                name: m.name,
                base: m.base.toString(),
                size: m.size,
                path: m.path
            }))
        });

        // Analyze main module
        const mainModule = modules[0];
        if (mainModule) {
            // Get imports
            const importedModules = mainModule.enumerateImports();
            send({
                type: 'analysis',
                category: 'imports',
                data: importedModules.map(i => ({
                    module: i.module,
                    name: i.name,
                    address: i.address ? i.address.toString() : null
                }))
            });

            // Search for protection-related strings
            const protectionKeywords = [
                'license', 'trial', 'debug', 'protect', 'check',
                'verify', 'validate', 'expire', 'crack', 'patch'
            ];

            Memory.scan(mainModule.base, mainModule.size, '00 00', {
                onMatch: function(address, size) {
                    try {
                        const str = address.readUtf8String();
                        if (str && str.length > 4 && str.length < 200) {
                            for (let keyword of protectionKeywords) {
                                if (str.toLowerCase().includes(keyword)) {
                                    strings.push(str);
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function() {
                    send({
                        type: 'analysis',
                        category: 'strings',
                        data: strings.slice(0, 100)  // Limit to 100 strings
                    });
                }
            });
        }

        // Detect common protection patterns
        const protectionAPIs = {
            'IsDebuggerPresent': 'anti_debug',
            'CheckRemoteDebuggerPresent': 'anti_debug',
            'GetTickCount': 'timing',
            'GetSystemTime': 'timing',
            'CryptHashData': 'integrity',
            'GetVolumeInformation': 'hardware',
            'RegQueryValueEx': 'registry',
            'InternetOpen': 'network'
        };

        const detectedAPIs = [];
        for (let [api, category] of Object.entries(protectionAPIs)) {
            const addr = Module.findExportByName(null, api);
            if (addr) {
                detectedAPIs.push({ api, category, found: true });
            }
        }

        send({
            type: 'analysis',
            category: 'protection_apis',
            data: detectedAPIs
        });
        """

    async def _detect_protections(self) -> None:
        """Detect protection mechanisms in the target.

        Uses multiple detection methods:
        1. FridaManager's built-in detector results
        2. Import analysis for protection APIs
        3. String analysis for protection keywords
        4. Heuristic guessing based on target software

        Populates:
        - self.detected_protections: Map of found protections
        - self.protection_evidence: Evidence for each detection

        Side Effects:
            - Updates metrics['protections_detected']
            - Updates progress for each detection

        """
        try:
            # Get detection results from FridaManager
            if hasattr(self.frida_manager, "detector"):
                detected = self.frida_manager.detector.get_detected_protections()

                # Combine all detection results
                if isinstance(detected, dict):
                    for prot_type_str, evidence in detected.items():
                        try:
                            prot_type = ProtectionType(prot_type_str)
                            self.detected_protections[prot_type] = True
                            if isinstance(evidence, list):
                                self.protection_evidence[prot_type] = evidence
                            else:
                                self.protection_evidence[prot_type] = [str(evidence)]
                        except ValueError as e:
                            logger.exception("Value error in frida_bypass_wizard: %s", e)

            # Analyze process-specific indicators
            if self.analysis_results["imports"]:
                self._analyze_imports_for_protections()

            if self.analysis_results["strings"]:
                self._analyze_strings_for_protections()

            # If no protections detected, try common ones based on target
            if not self.detected_protections and self.target_process:
                self._guess_protections_by_target()

            self.metrics["protections_detected"] = len(self.detected_protections)

            # Log detected protections
            for prot_type in self.detected_protections:
                self._update_progress(
                    30 + (5 * list(self.detected_protections.keys()).index(prot_type)),
                    f"Detected: {prot_type.value}",
                )

        except Exception as e:
            logger.exception("Protection detection failed: %s", e)

    def _analyze_imports_for_protections(self) -> None:
        """Analyze imported functions for protection indicators.

        Maps common protection-related API imports to protection types:

        - Debugger detection APIs -> ANTI_DEBUG
        - VM detection APIs -> ANTI_VM
        - Timing APIs -> TIME based protections
        - Crypto APIs -> INTEGRITY checks
        - Registry/hardware APIs -> LICENSE/HARDWARE

        Updates detected_protections and protection_evidence based on
        imports found in the target process.

        Complexity:
            Time: O(n) where n is number of imports
            Space: O(1)

        """
        protection_imports = {
            "IsDebuggerPresent": ProtectionType.ANTI_DEBUG,
            "CheckRemoteDebuggerPresent": ProtectionType.ANTI_DEBUG,
            "GetSystemFirmwareTable": ProtectionType.ANTI_VM,
            "GetTickCount": ProtectionType.TIME,
            "GetSystemTime": ProtectionType.TIME,
            "CryptHashData": ProtectionType.INTEGRITY,
            "GetVolumeInformation": ProtectionType.HARDWARE,
            "RegQueryValueEx": ProtectionType.LICENSE,
            "InternetOpen": ProtectionType.CLOUD,
            "DeviceIoControl": ProtectionType.KERNEL,
            "VirtualProtect": ProtectionType.MEMORY,
        }

        for imp in self.analysis_results["imports"]:
            func_name = imp.get("name", "")
            if func_name in protection_imports:
                prot_type = protection_imports[func_name]
                self.detected_protections[prot_type] = True
                if prot_type not in self.protection_evidence:
                    self.protection_evidence[prot_type] = []
                self.protection_evidence[prot_type].append(f"Import: {func_name}")

    def _analyze_strings_for_protections(self) -> None:
        """Analyze strings for protection indicators.

        Searches collected strings for keywords indicating protections:

        - 'license', 'trial' -> LICENSE protection
        - 'expire' -> TIME based protection
        - 'debug' -> ANTI_DEBUG
        - 'vmware', 'virtualbox' -> ANTI_VM
        - 'checksum', 'hash' -> INTEGRITY
        - 'hwid' -> HARDWARE binding
        - 'http', 'https' -> CLOUD validation

        Adds detected protections with string evidence.

        Complexity:
            Time: O(n*m) where n is strings, m is patterns
            Space: O(p) where p is detected protections

        """
        protection_patterns = {
            "license": ProtectionType.LICENSE,
            "trial": ProtectionType.TIME,
            "expire": ProtectionType.TIME,
            "debug": ProtectionType.ANTI_DEBUG,
            "vmware": ProtectionType.ANTI_VM,
            "virtualbox": ProtectionType.ANTI_VM,
            "checksum": ProtectionType.INTEGRITY,
            "hash": ProtectionType.INTEGRITY,
            "hwid": ProtectionType.HARDWARE,
            "http": ProtectionType.CLOUD,
            "https": ProtectionType.CLOUD,
        }

        for string in self.analysis_results["strings"]:
            string_lower = string.lower()
            for pattern, prot_type in protection_patterns.items():
                if pattern in string_lower:
                    self.detected_protections[prot_type] = True
                    if prot_type not in self.protection_evidence:
                        self.protection_evidence[prot_type] = []
                    self.protection_evidence[prot_type].append(f"String: {string[:50]}")

    def _guess_protections_by_target(self) -> None:
        """Guess likely protections based on target software."""
        if not self.target_process:
            return

        process_name = self.target_process.get("name", "").lower()

        self.detected_protections[ProtectionType.LICENSE] = True
        # Common patterns
        if "adobe" in process_name or "office" in process_name or "microsoft" in process_name:
            self.detected_protections[ProtectionType.CLOUD] = True
        elif "autodesk" in process_name:
            self.detected_protections[ProtectionType.HARDWARE] = True
        elif "vmware" in process_name:
            self.detected_protections[ProtectionType.TIME] = True

    async def _plan_strategy(self) -> None:
        """Plan the bypass strategy based on detected protections.

        Creates BypassStrategy objects for each detected protection:
        1. Retrieves recommended scripts from presets
        2. Sets priority based on protection type and config
        3. Establishes dependencies between strategies
        4. Sorts by priority and dependency order
        5. Limits to max_scripts configuration

        Strategy ordering ensures:
        - Dependencies are satisfied
        - High priority protections bypass first
        - Related protections are grouped

        Side Effects:
            - Populates self.strategies list
            - Updates progress to 50%

        """
        try:
            # Clear previous strategies
            self.strategies.clear()

            # Create strategies for each detected protection
            for prot_type in self.detected_protections:
                # Skip if in exclude list
                exclude_list = self.config.get("exclude")
                if isinstance(exclude_list, list) and prot_type.value in exclude_list:
                    continue

                # Get recommended scripts
                scripts = get_scripts_for_protection(prot_type.value)
                if not scripts:
                    continue

                # Create strategy
                strategy = BypassStrategy(prot_type, scripts)

                # Set priority based on configuration
                priority_list = self.config.get("priority", [])
                if isinstance(priority_list, list) and prot_type.value in priority_list:
                    strategy.priority = 100
                elif prot_type == ProtectionType.ANTI_DEBUG:
                    strategy.priority = 90
                elif prot_type == ProtectionType.LICENSE:
                    strategy.priority = 80

                # Set dependencies
                if prot_type == ProtectionType.LICENSE:
                    strategy.dependencies = [ProtectionType.ANTI_DEBUG]
                elif prot_type == ProtectionType.CLOUD:
                    strategy.dependencies = [ProtectionType.ANTI_DEBUG, ProtectionType.LICENSE]

                self.strategies.append(strategy)

            # Sort strategies by priority and dependencies
            self.strategies.sort(key=lambda s: (-s.priority, len(s.dependencies)))

            # Limit number of scripts based on configuration
            max_scripts_val = self.config.get("max_scripts", 10)
            max_scripts = int(max_scripts_val) if isinstance(max_scripts_val, (int, float)) else 10
            if len(self.strategies) > max_scripts:
                self.strategies = self.strategies[:max_scripts]

            self._update_progress(50, f"Planned {len(self.strategies)} bypass strategies")

        except Exception as e:
            logger.exception("Strategy planning failed: %s", e)

    async def _apply_bypasses(self) -> None:
        """Apply bypass strategies in order.

        Executes each bypass strategy sequentially:

        1. Checks if dependencies are satisfied
        2. Loads and executes bypass scripts
        3. Tracks success/failure for each strategy
        4. Updates metrics and progress

        Strategies are applied with small delays between them
        to avoid overwhelming the target.

        Side Effects:
            - Loads Frida scripts into target
            - Updates successful_bypasses/failed_bypasses sets
            - Updates metrics and progress (60-80%)

        Complexity:
            Time: O(n*m) where n is strategies, m is scripts per strategy
            Space: O(n) for tracking results

        """
        try:
            completed_protections: set[ProtectionType] = set()
            total_strategies = len(self.strategies)

            for i, strategy in enumerate(self.strategies):
                # Check dependencies
                if not strategy.can_apply(completed_protections):
                    logger.info("Skipping %s - dependencies not met", strategy.protection_type.value)
                    continue

                # Update progress
                progress = 60 + int((20 / total_strategies) * i) if total_strategies > 0 else 60
                self._update_progress(
                    progress,
                    f"Applying {strategy.protection_type.value} bypass...",
                )

                # Apply scripts
                success = await self._apply_strategy(strategy)

                if success:
                    completed_protections.add(strategy.protection_type)
                    self.successful_bypasses.add(strategy.protection_type)
                    strategy.success = True
                else:
                    self.failed_bypasses.add(strategy.protection_type)
                    strategy.success = False

                # Track that this bypass was executed (regardless of success)
                self.executed_bypasses.add(strategy.protection_type)
                self.applied_strategies.append(strategy)
                bypasses_attempted = self.metrics.get("bypasses_attempted", 0)
                if isinstance(bypasses_attempted, (int, float)):
                    self.metrics["bypasses_attempted"] = int(bypasses_attempted) + 1

                # Small delay between strategies
                await asyncio.sleep(0.5)

            self.metrics["bypasses_successful"] = len(self.successful_bypasses)

        except Exception as e:
            logger.exception("Bypass application failed: %s", e)

    async def _apply_strategy(self, strategy: BypassStrategy) -> bool:
        """Apply a single bypass strategy.

        Loads all scripts associated with a strategy into the target.
        Scripts are loaded with wizard-specific options including:
        - wizard_mode: True
        - protection_type: Type being bypassed
        - Additional mode-specific options

        Args:
            strategy: BypassStrategy to apply

        Returns:
            bool: True if at least one script loaded successfully

        Side Effects:
            - Loads scripts via FridaManager
            - Updates metrics['scripts_loaded']

        """
        try:
            success_count = 0

            for script_name in strategy.scripts:
                # Load script with wizard options
                options_val = self.config.get("options", {})
                options: dict[str, Any] = options_val.copy() if isinstance(options_val, dict) else {}
                options["wizard_mode"] = True
                options["protection_type"] = strategy.protection_type.value

                if hasattr(self.frida_manager, "load_script"):
                    if success := self.frida_manager.load_script(
                        self.session_id,
                        script_name,
                        options,
                    ):
                        logger.debug("Script load result: %s", success)
                        success_count += 1
                        scripts_loaded = self.metrics.get("scripts_loaded", 0)
                        if isinstance(scripts_loaded, (int, float)):
                            self.metrics["scripts_loaded"] = int(scripts_loaded) + 1
                        logger.info("Successfully loaded %s for %s", script_name, strategy.protection_type.value)
                    else:
                        logger.warning("Failed to load %s", script_name)

            # Consider strategy successful if at least one script loaded
            return success_count > 0

        except Exception as e:
            logger.exception("Strategy application failed: %s", e)
            return False

    async def _monitor_results(self) -> None:
        """Monitor and verify bypass results.

        Post-bypass verification phase:
        1. Waits for bypasses to take effect
        2. Verifies each bypass is working
        3. Attempts adaptive retry for failures

        Verification methods vary by protection type:
        - ANTI_DEBUG: Checks debugger detection APIs
        - ANTI_ATTACH: Tests hooking capability
        - SSL_PINNING: Verifies certificate validation

        Side Effects:
            - May load additional verification scripts
            - Triggers adaptive retry for failures
            - Updates progress to 95%

        """
        try:
            # Wait for bypasses to take effect
            await asyncio.sleep(2)

            # Check if protections are still active
            verification_results = {}

            for strategy in self.applied_strategies:
                if strategy.success:
                    # Verify bypass effectiveness
                    still_detected = await self._verify_bypass(strategy.protection_type)
                    verification_results[strategy.protection_type] = not still_detected

            # Update success metrics based on verification
            verified_count = sum(bool(v) for v in verification_results.values())
            self._update_progress(
                95,
                f"Verified {verified_count}/{len(verification_results)} bypasses",
            )

            # If some bypasses failed, try adaptive measures
            if verified_count < len(verification_results):
                await self._adaptive_retry(verification_results)

        except Exception as e:
            logger.exception("Result monitoring failed: %s", e)

    async def _verify_bypass(self, protection_type: ProtectionType) -> bool:
        """Verify if a protection is still active."""
        # Check if the specific protection is still being triggered
        logger.info("Verifying bypass for %s", protection_type.value)

        # Check if this protection type has been successfully bypassed
        if protection_type in self.executed_bypasses:
            # Verify based on protection type
            if protection_type == ProtectionType.ANTI_DEBUG:
                # Check for debugger detection
                return await self._check_anti_debug_active()
            if protection_type == ProtectionType.ANTI_ATTACH:
                # Check if attachment is blocked
                return await self._check_anti_attach_active()
            if protection_type == ProtectionType.SSL_PINNING:
                # Check if SSL pinning is enforced
                return await self._check_ssl_pinning_active()
            # Add more specific checks for other protection types

        # For now, return false (bypass successful) if protection was executed
        return protection_type not in self.executed_bypasses

    async def _check_anti_debug_active(self) -> bool:
        """Check if anti-debug protection is still active."""
        try:
            # Create detection script
            detection_script = """
            var detected = false;

            // Check for IsDebuggerPresent on Windows
            if (Process.platform === 'windows') {
                try {
                    var isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
                    if (isDebuggerPresent) {
                        var result = new NativeFunction(isDebuggerPresent, 'bool', [])();
                        if (result) detected = true;
                    }
                } catch(e) {}

                // Check PEB for debugger flag
                try {
                    var peb = Process.enumerateModules()[0].base;
                    var beingDebugged = peb.add(0x02).readU8();
                    if (beingDebugged) detected = true;
                } catch(e) {}
            }

            // Check for ptrace on Linux/Android
            if (Process.platform === 'linux' || Process.platform === 'android') {
                try {
                    var ptrace = Module.findExportByName(null, 'ptrace');
                    if (ptrace) {
                        // Try PTRACE_TRACEME
                        var ptraceFunc = new NativeFunction(ptrace, 'int', ['int', 'int', 'pointer', 'pointer']);
                        var result = ptraceFunc(0, 0, NULL, NULL);
                        if (result === -1) detected = true;
                    }
                } catch(e) {}
            }

            // Check common anti-debug tricks
            try {
                // Timing checks - loops should complete quickly if no debugger
                var start = Date.now();
                for (var i = 0; i < 1000000; i++) {}
                var elapsed = Date.now() - start;
                if (elapsed > 100) detected = true;  // Suspiciously slow - likely debugged
            } catch(e) {}

            send({type: 'detection', result: detected});
            """

            # Run detection script
            temp_script = Path("anti_debug_check.js")
            await asyncio.to_thread(lambda: temp_script.write_text(detection_script, encoding="utf-8"))

            result = await self._run_detection_script(temp_script)
            temp_script.unlink()

            detected_val = result.get("detected", False)
            return bool(detected_val) if isinstance(detected_val, (bool, int, str)) else False

        except Exception as e:
            logger.exception("Anti-debug detection failed: %s", e)
            return False

    async def _check_anti_attach_active(self) -> bool:
        """Check if anti-attach protection is still active."""
        try:
            # Create attach detection script
            detection_script = """
            var detected = false;

            // Try to detect if we can attach to critical functions
            try {
                // Test hooking capability
                var testTarget = Module.findExportByName(null, 'malloc');
                if (testTarget) {
                    Interceptor.attach(testTarget, {
                        onEnter: function(args) {
                            // If we can hook, anti-attach is not active
                        }
                    });
                    Interceptor.detachAll();
                }
            } catch(e) {
                // If attach fails, anti-attach is active
                detected = true;
            }

            // Check for hook detection mechanisms
            if (Process.platform === 'windows') {
                try {
                    // Check for common anti-attach APIs
                    var apis = [
                        'DbgUiRemoteBreakin',
                        'DbgBreakPoint',
                        'RtlIsDebuggerPresent'
                    ];

                    apis.forEach(function(api) {
                        var addr = Module.findExportByName('ntdll.dll', api);
                        if (addr) {
                            var bytes = addr.readByteArray(5);
                            // Check for common hooks/patches
                            if (bytes[0] === 0xE9 || bytes[0] === 0xFF) {
                                detected = true;
                            }
                        }
                    });
                } catch(e) {}
            }

            // Check process flags on Linux
            if (Process.platform === 'linux') {
                try {
                    var status = File.readAllText('/proc/self/status');
                    if (status.includes('TracerPid') && !status.includes('TracerPid:\t0')) {
                        detected = true;
                    }
                } catch(e) {}
            }

            send({type: 'detection', result: detected});
            """

            # Run detection script
            temp_script = Path("anti_attach_check.js")
            await asyncio.to_thread(lambda: temp_script.write_text(detection_script, encoding="utf-8"))

            result = await self._run_detection_script(temp_script)
            temp_script.unlink()

            detected_val = result.get("detected", False)
            return bool(detected_val) if isinstance(detected_val, (bool, int, str)) else False

        except Exception as e:
            logger.exception("Anti-attach detection failed: %s", e)
            return False

    async def _check_ssl_pinning_active(self) -> bool:
        """Check if SSL pinning is still active."""
        try:
            # Create SSL pinning detection script
            detection_script = """
            var detected = false;
            var sslHookActive = false;

            // Test if SSL pinning bypass is working
            try {
                // Android SSL pinning check
                if (Process.platform === 'android') {
                    // Check if common pinning methods are hooked
                    var pinningClasses = [
                        'com.android.org.conscrypt.TrustManagerImpl',
                        'okhttp3.CertificatePinner',
                        'com.squareup.okhttp.CertificatePinner',
                        'com.android.org.conscrypt.Platform'
                    ];

                    pinningClasses.forEach(function(className) {
                        try {
                            var clazz = Java.use(className);
                            // Check if methods are hooked
                            if (clazz.checkServerTrusted && clazz.checkServerTrusted.implementation) {
                                sslHookActive = true;
                            }
                        } catch(e) {}
                    });

                    // If no hooks are active, pinning is still enabled
                    detected = !sslHookActive;
                }

                // iOS SSL pinning check
                if (Process.platform === 'darwin') {
                    // Check SecTrust functions
                    var secTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
                    if (secTrustEvaluate) {
                        try {
                            Interceptor.attach(secTrustEvaluate, {
                                onEnter: function() {
                                    sslHookActive = true;
                                }
                            });
                            Interceptor.detachAll();
                        } catch(e) {
                            // If we can't hook, pinning might be active
                            detected = true;
                        }
                    }
                }

                // Generic HTTPS test
                if (!Process.platform === 'android' && !Process.platform === 'darwin') {
                    // Check if SSL/TLS functions are hooked
                    var sslFunctions = [
                        'SSL_verify_client_post_handshake',
                        'SSL_CTX_set_verify',
                        'X509_verify_cert'
                    ];

                    sslFunctions.forEach(function(func) {
                        var addr = Module.findExportByName(null, func);
                        if (addr) {
                            var bytes = addr.readByteArray(5);
                            // Check for hooks
                            if (bytes[0] === 0xE9 || bytes[0] === 0xFF) {
                                sslHookActive = true;
                            }
                        }
                    });

                    detected = !sslHookActive;
                }
            } catch(e) {
                // Error might indicate protection is active
                detected = true;
            }

            send({type: 'detection', result: detected});
            """

            # Run detection script
            temp_script = Path("ssl_pinning_check.js")
            await asyncio.to_thread(lambda: temp_script.write_text(detection_script, encoding="utf-8"))

            result = await self._run_detection_script(temp_script)
            temp_script.unlink()

            detected_val = result.get("detected", False)
            return bool(detected_val) if isinstance(detected_val, (bool, int, str)) else False

        except Exception as e:
            logger.exception("SSL pinning detection failed: %s", e)
            return False

    async def _run_detection_script(self, script_path: Path) -> dict[str, Any]:
        """Run a detection script and collect results."""
        result = {"detected": False}

        try:
            # Set up message handler to receive results
            def on_message(message: dict[str, Any], data: bytes | None) -> None:
                if message["type"] == "send":
                    payload = message["payload"]
                    if payload.get("type") == "detection":
                        result["detected"] = payload.get("result", False)
                elif message["type"] == "error" and data:
                    logger.exception("Script error with data: %s", data)

            # Load and run script with message handler
            if hasattr(self.frida_manager, "load_script"):
                script_loaded = self.frida_manager.load_script(
                    self.session_id,
                    str(script_path),
                    {"detection_mode": True},
                    message_handler=on_message,
                )
            else:
                script_loaded = False

            if script_loaded:
                # Wait for detection to complete
                await asyncio.sleep(0.5)

            return result

        except Exception as e:
            logger.exception("Detection script execution failed: %s", e)
            return {"detected": False}

    async def _adaptive_retry(self, verification_results: dict[ProtectionType, bool]) -> None:
        """Adaptively retry failed bypasses with alternative strategies."""
        retry_count = 0
        max_retries = 3

        for prot_type, success in verification_results.items():
            if not success and retry_count < max_retries:
                logger.info("Attempting adaptive retry for %s", prot_type.value)

                if alternative_strategy := self._get_alternative_strategy(prot_type):
                    try:
                        # Apply alternative bypass
                        retry_success = await self._apply_strategy(alternative_strategy)

                        if retry_success:
                            # Verify the alternative worked
                            await asyncio.sleep(0.5)
                            verify_success = await self._verify_bypass(prot_type)

                            retry_successes = self.metrics.get("retry_successes", 0)
                            retry_failures = self.metrics.get("retry_failures", 0)
                            if verify_success:
                                logger.info("Alternative strategy successful for %s", prot_type.value)
                                if isinstance(retry_successes, (int, float)):
                                    self.metrics["retry_successes"] = int(retry_successes) + 1
                            else:
                                logger.warning("Alternative strategy failed verification for %s", prot_type.value)
                                if isinstance(retry_failures, (int, float)):
                                    self.metrics["retry_failures"] = int(retry_failures) + 1
                        else:
                            retry_failures = self.metrics.get("retry_failures", 0)
                            if isinstance(retry_failures, (int, float)):
                                self.metrics["retry_failures"] = int(retry_failures) + 1

                    except Exception as e:
                        logger.exception("Adaptive retry failed for %s: %s", prot_type.value, e)
                        retry_failures = self.metrics.get("retry_failures", 0)
                        if isinstance(retry_failures, (int, float)):
                            self.metrics["retry_failures"] = int(retry_failures) + 1

                retry_count += 1

    def _get_alternative_strategy(self, protection_type: ProtectionType) -> BypassStrategy | None:
        """Get alternative bypass strategy for failed protection."""
        alternative_strategies = {
            ProtectionType.ANTI_DEBUG: BypassStrategy(
                protection_type=ProtectionType.ANTI_DEBUG,
                scripts=["alternatives/anti_debug_alt.js"],
                priority=70,
            ),
            ProtectionType.ANTI_ATTACH: BypassStrategy(
                protection_type=ProtectionType.ANTI_ATTACH,
                scripts=["alternatives/anti_attach_alt.js"],
                priority=70,
            ),
            ProtectionType.SSL_PINNING: BypassStrategy(
                protection_type=ProtectionType.SSL_PINNING,
                scripts=["alternatives/ssl_pinning_alt.js"],
                priority=80,
            ),
            ProtectionType.ROOT_DETECTION: BypassStrategy(
                protection_type=ProtectionType.ROOT_DETECTION,
                scripts=["alternatives/root_detection_alt.js"],
                priority=80,
            ),
            ProtectionType.INTEGRITY_CHECK: BypassStrategy(
                protection_type=ProtectionType.INTEGRITY_CHECK,
                scripts=["alternatives/integrity_alt.js"],
                priority=60,
            ),
        }

        return alternative_strategies.get(protection_type)

    def _generate_report(self) -> dict[str, Any]:
        """Generate comprehensive wizard report.

        Creates detailed report including:
        - Overall success status
        - Execution duration and mode
        - Process information
        - All detected protections with evidence
        - Bypass attempts and success rates
        - Applied strategies with outcomes
        - Performance metrics

        Returns:
            Dict with complete wizard execution report

        Report structure:
        {
            'success': bool,
            'mode': str,
            'duration': float,
            'process': {...},
            'detections': {...},
            'bypasses': {...},
            'strategies': [...],
            'metrics': {...}
        }

        """
        end_time = self.metrics.get("end_time")
        start_time = self.metrics.get("start_time")
        if isinstance(end_time, (int, float)) and isinstance(start_time, (int, float)):
            duration = float(end_time) - float(start_time)
        else:
            duration = 0.0

        bypasses_attempted = self.metrics.get("bypasses_attempted", 0)
        bypasses_successful = self.metrics.get("bypasses_successful", 0)
        attempted_int = int(bypasses_attempted) if isinstance(bypasses_attempted, (int, float)) else 0
        successful_int = int(bypasses_successful) if isinstance(bypasses_successful, (int, float)) else 0

        return {
            "success": self.state == WizardState.COMPLETE,
            "mode": self.mode,
            "duration": duration,
            "process": self.analysis_results["process_info"],
            "detections": {
                "total": self.metrics["protections_detected"],
                "types": [p.value for p in self.detected_protections],
                "evidence": {p.value: e for p, e in self.protection_evidence.items()},
            },
            "bypasses": {
                "attempted": attempted_int,
                "successful": successful_int,
                "failed": len(self.failed_bypasses),
                "success_rate": (successful_int / attempted_int * 100 if attempted_int > 0 else 0),
                "successful_types": [p.value for p in self.successful_bypasses],
                "failed_types": [p.value for p in self.failed_bypasses],
            },
            "strategies": [
                {
                    "protection": s.protection_type.value,
                    "scripts": s.scripts,
                    "success": s.success,
                }
                for s in self.applied_strategies
            ],
            "metrics": self.metrics,
        }

    def attach_to_process(
        self,
        pid: int | None = None,
        process_name: str | None = None,
    ) -> bool:
        """Attach to a target process for bypass operations.

        Establishes a Frida session with the target process either by PID
        or by process name. Required before injecting scripts or running
        bypass operations.

        Args:
            pid: Process ID to attach to (takes precedence over process_name)
            process_name: Name of process to attach to

        Returns:
            True if attachment succeeded, False otherwise

        Raises:
            ValueError: If neither pid nor process_name is provided

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> wizard.attach_to_process(
            ...     pid=1234
            ... )
            True
            >>> wizard.attach_to_process(
            ...     process_name="target.exe"
            ... )
            True
        """
        if pid is None and process_name is None:
            logger.exception("Either pid or process_name must be provided")
            return False

        try:
            if hasattr(self.frida_manager, "attach_to_process"):
                if pid is not None:
                    success = self.frida_manager.attach_to_process(pid)
                else:
                    success = self.frida_manager.attach_to_process(process_name)

                if success:
                    session_val = getattr(self.frida_manager, "session", None)
                    if hasattr(self, "session"):
                        self.session = session_val
                    self.target_process = {
                        "pid": pid or getattr(self.frida_manager, "target_pid", None),
                        "name": process_name or getattr(self.frida_manager, "target_name", "Unknown"),
                    }
                    logger.info("Successfully attached to process: %s", pid or process_name)
                    return True
                else:
                    logger.exception("Failed to attach to process: %s", pid or process_name)
                    return False
            else:
                logger.exception("FridaManager does not have attach_to_process method")
                return False

        except Exception as e:
            logger.exception("Exception during process attachment: %s", e)
            return False

    def detach(self) -> bool:
        """Detach from the currently attached process.

        Cleanly terminates the Frida session and releases all resources
        associated with the target process. Should be called when bypass
        operations are complete or when switching targets.

        Returns:
            True if detachment succeeded, False otherwise

        Side Effects:
            - Terminates active Frida session
            - Clears session and target_process attributes
            - Resets wizard state to IDLE

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> wizard.attach_to_process(
            ...     pid=1234
            ... )
            True
            >>> wizard.detach()
            True
        """
        try:
            if hasattr(self, "session") and self.session is not None:
                try:
                    self.session.detach()
                except Exception as e:
                    logger.warning("Error detaching session directly: %s", e)

            if hasattr(self.frida_manager, "detach"):
                self.frida_manager.detach()
            elif hasattr(self.frida_manager, "session") and self.frida_manager.session:
                try:
                    self.frida_manager.session.detach()
                except Exception as e:
                    logger.warning("Error detaching from frida_manager session: %s", e)

            self.session = None
            self.session_id = None
            self.target_process = None
            self._update_state(WizardState.IDLE)

            logger.info("Successfully detached from process")
            return True

        except Exception as e:
            logger.exception("Exception during detachment: %s", e)
            return False

    def inject_script(self, script_content: str, script_name: str = "bypass_script") -> bool:
        """Inject a Frida script into the attached process.

        Loads and executes JavaScript code in the context of the target process.
        The script can hook functions, intercept API calls, and modify behavior
        to bypass protection mechanisms.

        Args:
            script_content: JavaScript code to inject
            script_name: Identifier for the script (for logging and management)

        Returns:
            True if script injection succeeded, False otherwise

        Raises:
            RuntimeError: If not attached to a process

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> wizard.attach_to_process(
            ...     pid=1234
            ... )
            True
            >>> script = '''
            ... Interceptor.attach(Module.findExportByName(null, 'IsDebuggerPresent'), {
            ...     onLeave: function(retval) { retval.replace(0); }
            ... });
            ... '''
            >>> wizard.inject_script(
            ...     script,
            ...     "anti_debug_bypass",
            ... )
            True
        """
        if self.target_process is None:
            logger.exception("Not attached to any process. Call attach_to_process first.")
            return False

        try:
            session_id = self.session_id or getattr(self.frida_manager, "session_id", None)

            if hasattr(self.frida_manager, "load_script"):
                success = self.frida_manager.load_script(
                    session_id,
                    script_content,
                    {"script_name": script_name, "inline": True},
                )
            elif hasattr(self.frida_manager, "inject_script") and self.target_process:
                target_pid = self.target_process.get("pid")
                success = self.frida_manager.inject_script(target_pid, script_content)
            elif hasattr(self, "session") and self.session:
                script_obj = self.session.create_script(script_content)
                script_obj.load()
                success = True
            else:
                logger.exception("No suitable method found to inject script")
                return False

            if success:
                scripts_loaded = self.metrics.get("scripts_loaded", 0)
                if isinstance(scripts_loaded, (int, float)):
                    self.metrics["scripts_loaded"] = int(scripts_loaded) + 1
                logger.info("Successfully injected script: %s", script_name)
                return True
            else:
                logger.exception("Failed to inject script: %s", script_name)
                return False

        except Exception as e:
            logger.exception("Exception during script injection: %s", e)
            return False

    def detect_protections(self) -> dict[str, float]:
        """Detect protection mechanisms in the attached process.

        Analyzes the target process to identify active protection mechanisms
        such as anti-debugging, license validation, integrity checks, etc.
        Returns confidence scores for each detected protection type.

        Returns:
            Dictionary mapping protection type names to confidence scores (0.0-1.0)

        Raises:
            RuntimeError: If not attached to a process

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> wizard.attach_to_process(
            ...     pid=1234
            ... )
            True
            >>> detections = wizard.detect_protections()
            >>> detections
            {'ANTI_DEBUG': 0.95, 'LICENSE': 0.8, 'INTEGRITY': 0.6}
        """
        if self.target_process is None:
            logger.warning("Not attached to any process, returning empty detections")
            return {}

        try:
            detection_results: dict[str, float] = {}

            if hasattr(self.frida_manager, "detector"):
                detected = self.frida_manager.detector.get_detected_protections()
                for prot_type, evidence in detected.items():
                    confidence = min(1.0, len(evidence) * 0.2) if isinstance(evidence, list) else 0.8
                    detection_results[prot_type] = confidence

            if hasattr(self.frida_manager, "detect_protections"):
                additional = self.frida_manager.detect_protections()
                if isinstance(additional, dict):
                    for key, value in additional.items():
                        if isinstance(value, (int, float)):
                            detection_results[str(key)] = float(value)
                        else:
                            detection_results[str(key)] = 0.75

            for prot_type in self.detected_protections:
                prot_name = prot_type.value if hasattr(prot_type, "value") else str(prot_type)
                if prot_name not in detection_results:
                    detection_results[prot_name] = 0.7

            self.metrics["protections_detected"] = len(detection_results)
            logger.info("Detected %s protection mechanisms", len(detection_results))

            return detection_results

        except Exception as e:
            logger.exception("Exception during protection detection: %s", e)
            return {}

    def generate_bypass_script(self, protection_type: str) -> str | None:
        """Generate a Frida bypass script for a specific protection type.

        Creates JavaScript code tailored to bypass the specified protection
        mechanism. Uses protection-specific templates and patterns.

        Args:
            protection_type: Type of protection to bypass (e.g., 'ANTI_DEBUG',
                           'LICENSE', 'INTEGRITY', 'SSL_PINNING')

        Returns:
            JavaScript code string for bypassing the protection, or None if
            no bypass is available for the specified protection type

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> script = wizard.generate_bypass_script(
            ...     "ANTI_DEBUG"
            ... )
            >>> print(script[:50])
            'Interceptor.attach(Module.findExportByName...'
        """
        bypass_templates: dict[str, str] = {
            "ANTI_DEBUG": self._get_anti_debug_bypass_script(),
            "anti_debug": self._get_anti_debug_bypass_script(),
            "LICENSE": self._get_license_bypass_script(),
            "license": self._get_license_bypass_script(),
            "INTEGRITY": self._get_integrity_bypass_script(),
            "integrity": self._get_integrity_bypass_script(),
            "SSL_PINNING": self._get_ssl_pinning_bypass_script(),
            "ssl_pinning": self._get_ssl_pinning_bypass_script(),
            "TIME": self._get_time_bypass_script(),
            "time": self._get_time_bypass_script(),
            "HARDWARE": self._get_hardware_bypass_script(),
            "hardware": self._get_hardware_bypass_script(),
            "CLOUD": self._get_cloud_bypass_script(),
            "cloud": self._get_cloud_bypass_script(),
        }

        if script := bypass_templates.get(protection_type):
            logger.info("Generated bypass script for protection: %s", protection_type)
            return script

        if scripts := get_scripts_for_protection(protection_type):
            script_path = Path(__file__).parent.parent / "scripts" / "frida" / scripts[0]
            if script_path.exists():
                return script_path.read_text(encoding="utf-8")

        logger.warning("No bypass script available for protection: %s", protection_type)
        return None

    def analyze_protections(self) -> dict[str, list[str]]:
        """Analyze protection mechanisms in the attached process.

        Performs comprehensive analysis of the target process to identify
        protection mechanisms, their implementations, and potential bypass
        approaches.

        Returns:
            Dictionary mapping protection categories to lists of findings

        Example:
            >>> wizard = FridaBypassWizard(
            ...     frida_manager
            ... )
            >>> wizard.attach_to_process(
            ...     pid=1234
            ... )
            True
            >>> analysis = wizard.analyze_protections()
            >>> analysis["Anti-Debug"]
            ['IsDebuggerPresent hook detected', 'PEB.BeingDebugged flag checked']
        """
        analysis_result: dict[str, list[str]] = {
            "Anti-Debug": [],
            "License Validation": [],
            "Integrity Checks": [],
            "Network Protection": [],
            "Time-Based Protection": [],
            "Hardware Binding": [],
            "Obfuscation": [],
        }

        try:
            if self.analysis_results.get("imports"):
                import_analysis = self._analyze_imports_for_report()
                for category, findings in import_analysis.items():
                    if category in analysis_result:
                        analysis_result[category].extend(findings)

            if self.analysis_results.get("strings"):
                string_analysis = self._analyze_strings_for_report()
                for category, findings in string_analysis.items():
                    if category in analysis_result:
                        analysis_result[category].extend(findings)

            if self.protection_evidence:
                for prot_type, evidence_list in self.protection_evidence.items():
                    prot_name = prot_type.value if hasattr(prot_type, "value") else str(prot_type)
                    category = self._map_protection_to_category(prot_name)
                    if category in analysis_result and isinstance(evidence_list, list):
                        analysis_result[category].extend(evidence_list)

            analysis_result = {k: v for k, v in analysis_result.items() if v}

            logger.info("Protection analysis completed: %s categories with findings", len(analysis_result))
            return analysis_result

        except Exception as e:
            logger.exception("Exception during protection analysis: %s", e)
            return {"Error": [str(e)]}

    def _get_anti_debug_bypass_script(self) -> str:
        """Return Frida script for anti-debugging bypass."""
        return """
(function() {
    'use strict';

    if (Process.platform === 'windows') {
        var isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (isDebuggerPresent) {
            Interceptor.attach(isDebuggerPresent, {
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
        }

        var checkRemoteDebugger = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (checkRemoteDebugger) {
            Interceptor.attach(checkRemoteDebugger, {
                onEnter: function(args) {
                    this.pbDebuggerPresent = args[1];
                },
                onLeave: function(retval) {
                    if (this.pbDebuggerPresent) {
                        this.pbDebuggerPresent.writeU32(0);
                    }
                    retval.replace(1);
                }
            });
        }

        var ntQueryInfo = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (ntQueryInfo) {
            Interceptor.attach(ntQueryInfo, {
                onEnter: function(args) {
                    this.infoClass = args[1].toInt32();
                    this.buffer = args[2];
                },
                onLeave: function(retval) {
                    if (this.infoClass === 7 || this.infoClass === 0x1e || this.infoClass === 0x1f) {
                        if (this.buffer) {
                            this.buffer.writePointer(ptr(0));
                        }
                    }
                }
            });
        }
    }

    send({type: 'bypass', name: 'anti_debug', status: 'active'});
})();
"""

    def _get_license_bypass_script(self) -> str:
        """Return Frida script for license validation bypass."""
        return """
(function() {
    'use strict';

    var licensePatterns = [
        'ValidateLicense', 'CheckLicense', 'IsLicensed', 'VerifyLicense',
        'CheckRegistration', 'IsRegistered', 'ValidateSerial', 'CheckSerial',
        'IsActivated', 'CheckActivation', 'ValidateKey', 'CheckKey'
    ];

    Process.enumerateModules().forEach(function(module) {
        if (module.name.toLowerCase().indexOf('license') !== -1 ||
            module.name.toLowerCase().indexOf('protect') !== -1) {

            module.enumerateExports().forEach(function(exp) {
                licensePatterns.forEach(function(pattern) {
                    if (exp.name.toLowerCase().indexOf(pattern.toLowerCase()) !== -1) {
                        try {
                            Interceptor.attach(exp.address, {
                                onLeave: function(retval) {
                                    retval.replace(1);
                                }
                            });
                            send({type: 'hook', target: exp.name, module: module.name});
                        } catch(e) {}
                    }
                });
            });
        }
    });

    if (Process.platform === 'windows') {
        var regQueryValue = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        if (regQueryValue) {
            Interceptor.attach(regQueryValue, {
                onEnter: function(args) {
                    this.valueName = args[1].readUtf16String();
                },
                onLeave: function(retval) {
                    if (this.valueName && (
                        this.valueName.toLowerCase().indexOf('license') !== -1 ||
                        this.valueName.toLowerCase().indexOf('serial') !== -1 ||
                        this.valueName.toLowerCase().indexOf('registration') !== -1)) {
                        retval.replace(0);
                    }
                }
            });
        }
    }

    send({type: 'bypass', name: 'license', status: 'active'});
})();
"""

    def _get_integrity_bypass_script(self) -> str:
        """Return Frida script for integrity check bypass."""
        return """
(function() {
    'use strict';

    var hashFunctions = [
        {dll: 'advapi32.dll', name: 'CryptHashData'},
        {dll: 'bcrypt.dll', name: 'BCryptHashData'},
        {dll: null, name: 'MD5_Update'},
        {dll: null, name: 'SHA1_Update'},
        {dll: null, name: 'SHA256_Update'}
    ];

    hashFunctions.forEach(function(func) {
        var addr = Module.findExportByName(func.dll, func.name);
        if (addr) {
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    send({type: 'integrity_call', function: func.name});
                }
            });
        }
    });

    var verifyFunctions = ['VerifySignature', 'CryptVerifySignature', 'CheckIntegrity'];
    verifyFunctions.forEach(function(name) {
        var addr = Module.findExportByName(null, name);
        if (addr) {
            Interceptor.attach(addr, {
                onLeave: function(retval) {
                    retval.replace(1);
                }
            });
        }
    });

    send({type: 'bypass', name: 'integrity', status: 'active'});
})();
"""

    def _get_ssl_pinning_bypass_script(self) -> str:
        """Return Frida script for SSL pinning bypass."""
        return """
(function() {
    'use strict';

    if (Process.platform === 'windows') {
        var winHttpSendRequest = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
        if (winHttpSendRequest) {
            Interceptor.attach(winHttpSendRequest, {
                onLeave: function(retval) {}
            });
        }

        var certVerify = Module.findExportByName('crypt32.dll', 'CertVerifyCertificateChainPolicy');
        if (certVerify) {
            Interceptor.attach(certVerify, {
                onLeave: function(retval) {
                    retval.replace(1);
                }
            });
        }
    }

    var sslVerifyFunctions = [
        'SSL_CTX_set_verify',
        'SSL_set_verify',
        'X509_verify_cert'
    ];

    sslVerifyFunctions.forEach(function(name) {
        var addr = Module.findExportByName(null, name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    if (name.indexOf('set_verify') !== -1) {
                        args[1] = ptr(0);
                    }
                },
                onLeave: function(retval) {
                    if (name === 'X509_verify_cert') {
                        retval.replace(1);
                    }
                }
            });
        }
    });

    send({type: 'bypass', name: 'ssl_pinning', status: 'active'});
})();
"""

    def _get_time_bypass_script(self) -> str:
        """Return Frida script for time-based protection bypass."""
        return """
(function() {
    'use strict';

    var targetTime = new Date('2025-01-01').getTime();

    if (Process.platform === 'windows') {
        var getSystemTime = Module.findExportByName('kernel32.dll', 'GetSystemTime');
        if (getSystemTime) {
            Interceptor.attach(getSystemTime, {
                onLeave: function(retval) {}
            });
        }

        var getLocalTime = Module.findExportByName('kernel32.dll', 'GetLocalTime');
        if (getLocalTime) {
            Interceptor.attach(getLocalTime, {
                onLeave: function(retval) {}
            });
        }

        var getTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        if (getTickCount) {
            Interceptor.attach(getTickCount, {
                onLeave: function(retval) {
                    retval.replace(1000);
                }
            });
        }
    }

    send({type: 'bypass', name: 'time', status: 'active'});
})();
"""

    def _get_hardware_bypass_script(self) -> str:
        """Return Frida script for hardware ID bypass."""
        return """
(function() {
    'use strict';

    var spoofedValues = {
        'CPUID': '00000000-0000-0000-0000-000000000000',
        'MAC': '00:11:22:33:44:55',
        'HDD': 'SPOOF-HDD-SERIAL-12345',
        'BIOS': 'SPOOF-BIOS-SERIAL-12345'
    };

    if (Process.platform === 'windows') {
        var getVolumeInfo = Module.findExportByName('kernel32.dll', 'GetVolumeInformationW');
        if (getVolumeInfo) {
            Interceptor.attach(getVolumeInfo, {
                onEnter: function(args) {
                    this.serialPtr = args[3];
                },
                onLeave: function(retval) {
                    if (this.serialPtr && !this.serialPtr.isNull()) {
                        this.serialPtr.writeU32(0x12345678);
                    }
                }
            });
        }

        var getComputerName = Module.findExportByName('kernel32.dll', 'GetComputerNameW');
        if (getComputerName) {
            Interceptor.attach(getComputerName, {
                onLeave: function(retval) {}
            });
        }
    }

    send({type: 'bypass', name: 'hardware', status: 'active'});
})();
"""

    def _get_cloud_bypass_script(self) -> str:
        """Return Frida script for cloud license bypass."""
        return """
(function() {
    'use strict';

    if (Process.platform === 'windows') {
        var internetConnect = Module.findExportByName('wininet.dll', 'InternetConnectW');
        if (internetConnect) {
            Interceptor.attach(internetConnect, {
                onEnter: function(args) {
                    this.server = args[1].readUtf16String();
                    send({type: 'network', action: 'connect', server: this.server});
                }
            });
        }

        var httpSendRequest = Module.findExportByName('wininet.dll', 'HttpSendRequestW');
        if (httpSendRequest) {
            Interceptor.attach(httpSendRequest, {
                onLeave: function(retval) {
                    retval.replace(1);
                }
            });
        }

        var internetReadFile = Module.findExportByName('wininet.dll', 'InternetReadFile');
        if (internetReadFile) {
            Interceptor.attach(internetReadFile, {
                onEnter: function(args) {
                    this.buffer = args[1];
                    this.bytesRead = args[3];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 && this.buffer) {
                        var successResponse = '{"status":"success","licensed":true,"valid":true}';
                        this.buffer.writeUtf8String(successResponse);
                        if (this.bytesRead) {
                            this.bytesRead.writeU32(successResponse.length);
                        }
                    }
                }
            });
        }
    }

    send({type: 'bypass', name: 'cloud', status: 'active'});
})();
"""

    def _analyze_imports_for_report(self) -> dict[str, list[str]]:
        """Analyze imports and return categorized findings."""
        findings: dict[str, list[str]] = {
            "Anti-Debug": [],
            "License Validation": [],
            "Integrity Checks": [],
            "Network Protection": [],
            "Time-Based Protection": [],
            "Hardware Binding": [],
        }

        import_categories = {
            "IsDebuggerPresent": "Anti-Debug",
            "CheckRemoteDebuggerPresent": "Anti-Debug",
            "NtQueryInformationProcess": "Anti-Debug",
            "RegQueryValueEx": "License Validation",
            "RegOpenKeyEx": "License Validation",
            "CryptHashData": "Integrity Checks",
            "BCryptHashData": "Integrity Checks",
            "InternetOpen": "Network Protection",
            "WinHttpOpen": "Network Protection",
            "GetSystemTime": "Time-Based Protection",
            "GetTickCount": "Time-Based Protection",
            "GetVolumeInformation": "Hardware Binding",
            "GetComputerName": "Hardware Binding",
        }

        for imp in self.analysis_results.get("imports", []):
            func_name = imp.get("name", "")
            if func_name in import_categories:
                category = import_categories[func_name]
                findings[category].append(f"Import: {func_name} from {imp.get('module', 'unknown')}")

        return findings

    def _analyze_strings_for_report(self) -> dict[str, list[str]]:
        """Analyze strings and return categorized findings."""
        findings: dict[str, list[str]] = {
            "Anti-Debug": [],
            "License Validation": [],
            "Integrity Checks": [],
            "Network Protection": [],
            "Time-Based Protection": [],
            "Hardware Binding": [],
        }

        string_patterns = {
            "debug": "Anti-Debug",
            "license": "License Validation",
            "serial": "License Validation",
            "registration": "License Validation",
            "checksum": "Integrity Checks",
            "hash": "Integrity Checks",
            "http": "Network Protection",
            "activation": "Network Protection",
            "trial": "Time-Based Protection",
            "expire": "Time-Based Protection",
            "hwid": "Hardware Binding",
            "hardware": "Hardware Binding",
        }

        strings_list = self.analysis_results.get("strings", [])
        strings_to_check = strings_list[:50] if isinstance(strings_list, list) else []
        for string in strings_to_check:
            string_lower = string.lower()
            for pattern, category in string_patterns.items():
                if pattern in string_lower:
                    findings[category].append(f"String: {string[:60]}")
                    break

        return findings

    def _map_protection_to_category(self, protection_name: str) -> str:
        """Map protection type name to analysis category."""
        category_map = {
            "ANTI_DEBUG": "Anti-Debug",
            "ANTI_ATTACH": "Anti-Debug",
            "LICENSE": "License Validation",
            "INTEGRITY": "Integrity Checks",
            "SSL_PINNING": "Network Protection",
            "CLOUD": "Network Protection",
            "TIME": "Time-Based Protection",
            "HARDWARE": "Hardware Binding",
        }
        return category_map.get(protection_name.upper(), "License Validation")

    def stop(self) -> None:
        """Stop the wizard if running.

        Gracefully stops wizard execution at current stage.
        Only stops if wizard is actively running (not idle/complete/failed).

        Side Effects:
            - Changes state to FAILED
            - Updates progress with stop message
            - Does not clean up already applied bypasses

        """
        if self.state not in [WizardState.COMPLETE, WizardState.FAILED, WizardState.IDLE]:
            self._update_state(WizardState.FAILED)
            self._update_progress(self.progress, "Wizard stopped by user")


class WizardPresetManager:
    """Manage wizard presets and quick configurations.

    Provides utilities for applying pre-configured bypass strategies
    based on known software patterns. Simplifies wizard usage for
    common targets.
    """

    @staticmethod
    def apply_software_preset(wizard: FridaBypassWizard, software_name: str) -> None:
        """Apply preset configuration based on software.

        Loads software-specific bypass configuration including:
        - Known protection types
        - Recommended scripts
        - Optimal execution order
        - Software-specific options

        Args:
            wizard: FridaBypassWizard instance to configure
            software_name: Name of target software (e.g., 'adobe', 'microsoft')

        Side Effects:
            - Overrides wizard.config with preset values
            - Logs preset application

        Example:
            WizardPresetManager.apply_software_preset(wizard, 'adobe')

        """
        preset = get_preset_by_software(software_name)

        # Create custom wizard config from preset
        custom_config = {
            "name": f"{software_name} Preset",
            "description": preset.get("description", ""),
            "detection_first": True,
            "max_scripts": len(preset.get("scripts", [])),
            "priority": preset.get("protections", []),
            "exclude": [],
            "options": preset.get("options", {}),
        }

        # Override wizard config
        wizard.config = custom_config
        logger.info("Applied preset for: %s", software_name)

    @staticmethod
    def create_custom_wizard(config: dict[str, Any]) -> "FridaBypassWizard":
        """Create wizard with custom configuration.

        Factory method for creating pre-configured wizard instances.
        Supports full customization of wizard behavior.

        Args:
            config: Custom configuration dictionary with:
                   - mode: Operating mode (safe/balanced/aggressive).
                   - priority: List of prioritized protection types.
                   - exclude: Protection types to skip.
                   - max_scripts: Maximum scripts to load.
                   - options: Additional script options.

        Returns:
            FridaBypassWizard: Configured wizard instance.

        Raises:
            ImportError: If FridaManager is not available.

        Example:
            wizard = WizardPresetManager.create_custom_wizard({
                'mode': 'aggressive',
                'priority': ['LICENSE', 'ANTI_DEBUG'],
                'max_scripts': 20
            })

        """
        try:
            from .frida_manager import FridaManager as _FridaManager
        except ImportError as e:
            raise ImportError("FridaManager not available") from e

        manager = _FridaManager()
        wizard = FridaBypassWizard(manager)

        # Apply custom configuration
        if "mode" in config:
            wizard.set_mode(config["mode"])

        # Override specific settings
        for key, value in config.items():
            if key in wizard.config:
                wizard.config[key] = value

        return wizard


# Export main components
__all__ = [
    "BypassStrategy",
    "FridaBypassWizard",
    "WizardPresetManager",
    "WizardState",
]
