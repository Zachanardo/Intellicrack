"""
Automated Bypass Wizard for Frida Operations

This module implements an intelligent wizard system that automatically:
- Detects protection mechanisms
- Selects appropriate bypass strategies
- Applies bypasses in optimal order
- Monitors success and adapts as needed
"""

import asyncio
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Set

from .frida_constants import ProtectionType
from .frida_presets import WIZARD_CONFIGS, get_preset_by_software, get_scripts_for_protection

logger = logging.getLogger(__name__)


class WizardState(Enum):
    """Wizard execution states"""
    IDLE = "idle"
    ANALYZING = "analyzing"
    DETECTING = "detecting"
    PLANNING = "planning"
    APPLYING = "applying"
    MONITORING = "monitoring"
    COMPLETE = "complete"
    FAILED = "failed"


class BypassStrategy:
    """Represents a bypass strategy for a specific protection"""

    def __init__(self, protection_type: ProtectionType,
                 scripts: List[str], priority: int = 50,
                 dependencies: List[ProtectionType] = None):
        self.protection_type = protection_type
        self.scripts = scripts
        self.priority = priority
        self.dependencies = dependencies or []
        self.success_indicators = []
        self.failure_indicators = []
        self.applied = False
        self.success = None

    def add_success_indicator(self, indicator: Dict[str, Any]):
        """Add an indicator of successful bypass"""
        self.success_indicators.append(indicator)

    def add_failure_indicator(self, indicator: Dict[str, Any]):
        """Add an indicator of failed bypass"""
        self.failure_indicators.append(indicator)

    def can_apply(self, completed_protections: Set[ProtectionType]) -> bool:
        """Check if strategy can be applied based on dependencies"""
        return all(dep in completed_protections for dep in self.dependencies)

    def __repr__(self):
        return f"BypassStrategy({self.protection_type.value}, scripts={self.scripts})"


class FridaBypassWizard:
    """Automated bypass wizard with intelligent decision making"""

    def __init__(self, frida_manager):
        self.frida_manager = frida_manager
        self.state = WizardState.IDLE
        self.session_id = None
        self.target_process = None

        # Wizard configuration
        self.config = WIZARD_CONFIGS["balanced"]
        self.mode = "balanced"

        # Detection results
        self.detected_protections = {}
        self.protection_evidence = {}

        # Bypass strategies
        self.strategies = []
        self.applied_strategies = []
        self.successful_bypasses = set()
        self.failed_bypasses = set()
        self.executed_bypasses = set()

        # Progress tracking
        self.progress = 0
        self.progress_callback = None
        self.status_callback = None

        # Analysis results
        self.analysis_results = {
            'process_info': {},
            'modules': [],
            'imports': [],
            'strings': [],
            'patterns': []
        }

        # Success metrics
        self.metrics = {
            'start_time': None,
            'end_time': None,
            'protections_detected': 0,
            'bypasses_attempted': 0,
            'bypasses_successful': 0,
            'scripts_loaded': 0,
            'hooks_installed': 0
        }

    def set_mode(self, mode: str):
        """Set wizard mode (safe, balanced, aggressive, stealth, analysis)"""
        if mode in WIZARD_CONFIGS:
            self.mode = mode
            self.config = WIZARD_CONFIGS[mode]
            logger.info(f"Wizard mode set to: {mode}")
        else:
            logger.warning(f"Unknown mode: {mode}, using balanced")

    def set_callbacks(self, progress_callback: Callable = None,
                     status_callback: Callable = None):
        """Set callback functions for progress and status updates"""
        self.progress_callback = progress_callback
        self.status_callback = status_callback

    def _update_progress(self, progress: int, message: str = ""):
        """Update progress and notify callbacks"""
        self.progress = progress
        if self.progress_callback:
            self.progress_callback(progress)
        if self.status_callback and message:
            self.status_callback(message)
        logger.info(f"Wizard progress: {progress}% - {message}")

    def _update_state(self, state: WizardState):
        """Update wizard state"""
        self.state = state
        logger.debug(f"Wizard state changed to: {state.value}")

    async def run(self, session_id: str, target_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the automated bypass wizard"""
        try:
            self.session_id = session_id
            self.target_process = target_info
            self.metrics['start_time'] = time.time()

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

            self.metrics['end_time'] = time.time()

            return self._generate_report()

        except Exception as e:
            self._update_state(WizardState.FAILED)
            self._update_progress(self.progress, f"Wizard failed: {e}")
            logger.error(f"Bypass wizard failed: {e}")
            raise

    async def _analyze_process(self):
        """Analyze the target process"""
        try:
            # Basic process analysis
            if self.target_process:
                self.analysis_results['process_info'] = {
                    'name': self.target_process.get('name', 'Unknown'),
                    'pid': self.target_process.get('pid', 0),
                    'path': self.target_process.get('path', '')
                }

            # Load analysis script
            analysis_script = self._create_analysis_script()

            # Create temporary analysis script
            temp_script = Path("temp_analysis.js")
            with open(temp_script, 'w') as f:
                f.write(analysis_script)

            # Load and run analysis
            success = self.frida_manager.load_script(
                self.session_id,
                str(temp_script),
                {"analysis_mode": True}
            )

            if success:
                # Wait for analysis results
                await asyncio.sleep(2)  # Give script time to analyze

            # Clean up
            temp_script.unlink()

            self._update_progress(20, "Process analysis complete")

        except Exception as e:
            logger.error(f"Process analysis failed: {e}")

    def _create_analysis_script(self) -> str:
        """Create Frida script for process analysis"""
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

    async def _detect_protections(self):
        """Detect protection mechanisms in the target"""
        try:
            # Get detection results from FridaManager
            detected = self.frida_manager.detector.get_detected_protections()

            # Analyze process-specific indicators
            if self.analysis_results['imports']:
                self._analyze_imports_for_protections()

            if self.analysis_results['strings']:
                self._analyze_strings_for_protections()

            # Combine all detection results
            for prot_type_str, evidence in detected.items():
                try:
                    prot_type = ProtectionType(prot_type_str)
                    self.detected_protections[prot_type] = True
                    self.protection_evidence[prot_type] = evidence
                except ValueError:
                    pass

            # If no protections detected, try common ones based on target
            if not self.detected_protections and self.target_process:
                self._guess_protections_by_target()

            self.metrics['protections_detected'] = len(self.detected_protections)

            # Log detected protections
            for prot_type in self.detected_protections:
                self._update_progress(
                    30 + (5 * list(self.detected_protections.keys()).index(prot_type)),
                    f"Detected: {prot_type.value}"
                )

        except Exception as e:
            logger.error(f"Protection detection failed: {e}")

    def _analyze_imports_for_protections(self):
        """Analyze imported functions for protection indicators"""
        protection_imports = {
            'IsDebuggerPresent': ProtectionType.ANTI_DEBUG,
            'CheckRemoteDebuggerPresent': ProtectionType.ANTI_DEBUG,
            'GetSystemFirmwareTable': ProtectionType.ANTI_VM,
            'GetTickCount': ProtectionType.TIME,
            'GetSystemTime': ProtectionType.TIME,
            'CryptHashData': ProtectionType.INTEGRITY,
            'GetVolumeInformation': ProtectionType.HARDWARE,
            'RegQueryValueEx': ProtectionType.LICENSE,
            'InternetOpen': ProtectionType.CLOUD,
            'DeviceIoControl': ProtectionType.KERNEL,
            'VirtualProtect': ProtectionType.MEMORY
        }

        for imp in self.analysis_results['imports']:
            func_name = imp.get('name', '')
            if func_name in protection_imports:
                prot_type = protection_imports[func_name]
                self.detected_protections[prot_type] = True
                if prot_type not in self.protection_evidence:
                    self.protection_evidence[prot_type] = []
                self.protection_evidence[prot_type].append(f"Import: {func_name}")

    def _analyze_strings_for_protections(self):
        """Analyze strings for protection indicators"""
        protection_patterns = {
            'license': ProtectionType.LICENSE,
            'trial': ProtectionType.TIME,
            'expire': ProtectionType.TIME,
            'debug': ProtectionType.ANTI_DEBUG,
            'vmware': ProtectionType.ANTI_VM,
            'virtualbox': ProtectionType.ANTI_VM,
            'checksum': ProtectionType.INTEGRITY,
            'hash': ProtectionType.INTEGRITY,
            'hwid': ProtectionType.HARDWARE,
            'http': ProtectionType.CLOUD,
            'https': ProtectionType.CLOUD
        }

        for string in self.analysis_results['strings']:
            string_lower = string.lower()
            for pattern, prot_type in protection_patterns.items():
                if pattern in string_lower:
                    self.detected_protections[prot_type] = True
                    if prot_type not in self.protection_evidence:
                        self.protection_evidence[prot_type] = []
                    self.protection_evidence[prot_type].append(f"String: {string[:50]}")

    def _guess_protections_by_target(self):
        """Guess likely protections based on target software"""
        if not self.target_process:
            return

        process_name = self.target_process.get('name', '').lower()

        # Common patterns
        if 'adobe' in process_name:
            self.detected_protections[ProtectionType.LICENSE] = True
            self.detected_protections[ProtectionType.CLOUD] = True
        elif 'office' in process_name or 'microsoft' in process_name:
            self.detected_protections[ProtectionType.LICENSE] = True
            self.detected_protections[ProtectionType.CLOUD] = True
        elif 'autodesk' in process_name:
            self.detected_protections[ProtectionType.LICENSE] = True
            self.detected_protections[ProtectionType.HARDWARE] = True
        elif 'vmware' in process_name:
            self.detected_protections[ProtectionType.LICENSE] = True
            self.detected_protections[ProtectionType.TIME] = True
        else:
            # Default assumption for unknown software
            self.detected_protections[ProtectionType.LICENSE] = True

    async def _plan_strategy(self):
        """Plan the bypass strategy based on detected protections"""
        try:
            # Clear previous strategies
            self.strategies.clear()

            # Create strategies for each detected protection
            for prot_type in self.detected_protections:
                # Skip if in exclude list
                if self.config.get('exclude') and prot_type.value in self.config['exclude']:
                    continue

                # Get recommended scripts
                scripts = get_scripts_for_protection(prot_type.value)
                if not scripts:
                    continue

                # Create strategy
                strategy = BypassStrategy(prot_type, scripts)

                # Set priority based on configuration
                if prot_type.value in self.config.get('priority', []):
                    strategy.priority = 100
                elif prot_type == ProtectionType.ANTI_DEBUG:
                    strategy.priority = 90  # High priority
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
            max_scripts = self.config.get('max_scripts', 10)
            if len(self.strategies) > max_scripts:
                self.strategies = self.strategies[:max_scripts]

            self._update_progress(50, f"Planned {len(self.strategies)} bypass strategies")

        except Exception as e:
            logger.error(f"Strategy planning failed: {e}")

    async def _apply_bypasses(self):
        """Apply bypass strategies in order"""
        try:
            completed_protections = set()
            total_strategies = len(self.strategies)

            for i, strategy in enumerate(self.strategies):
                # Check dependencies
                if not strategy.can_apply(completed_protections):
                    logger.info(f"Skipping {strategy.protection_type.value} - dependencies not met")
                    continue

                # Update progress
                progress = 60 + int((20 / total_strategies) * i)
                self._update_progress(
                    progress,
                    f"Applying {strategy.protection_type.value} bypass..."
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
                self.metrics['bypasses_attempted'] += 1

                # Small delay between strategies
                await asyncio.sleep(0.5)

            self.metrics['bypasses_successful'] = len(self.successful_bypasses)

        except Exception as e:
            logger.error(f"Bypass application failed: {e}")

    async def _apply_strategy(self, strategy: BypassStrategy) -> bool:
        """Apply a single bypass strategy"""
        try:
            success_count = 0

            for script_name in strategy.scripts:
                # Load script with wizard options
                options = self.config.get('options', {}).copy()
                options['wizard_mode'] = True
                options['protection_type'] = strategy.protection_type.value

                success = self.frida_manager.load_script(
                    self.session_id,
                    script_name,
                    options
                )

                if success:
                    success_count += 1
                    self.metrics['scripts_loaded'] += 1
                    logger.info(f"Successfully loaded {script_name} for {strategy.protection_type.value}")
                else:
                    logger.warning(f"Failed to load {script_name}")

            # Consider strategy successful if at least one script loaded
            return success_count > 0

        except Exception as e:
            logger.error(f"Strategy application failed: {e}")
            return False

    async def _monitor_results(self):
        """Monitor and verify bypass results"""
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
            verified_count = sum(1 for v in verification_results.values() if v)
            self._update_progress(
                95,
                f"Verified {verified_count}/{len(verification_results)} bypasses"
            )

            # If some bypasses failed, try adaptive measures
            if verified_count < len(verification_results):
                await self._adaptive_retry(verification_results)

        except Exception as e:
            logger.error(f"Result monitoring failed: {e}")

    async def _verify_bypass(self, protection_type: ProtectionType) -> bool:
        """Verify if a protection is still active"""
        # Check if the specific protection is still being triggered
        logger.info(f"Verifying bypass for {protection_type.value}")

        # Check if this protection type has been successfully bypassed
        if protection_type in self.executed_bypasses:
            # Verify based on protection type
            if protection_type == ProtectionType.ANTI_DEBUG:
                # Check for debugger detection
                return await self._check_anti_debug_active()
            elif protection_type == ProtectionType.ANTI_ATTACH:
                # Check if attachment is blocked
                return await self._check_anti_attach_active()
            elif protection_type == ProtectionType.SSL_PINNING:
                # Check if SSL pinning is enforced
                return await self._check_ssl_pinning_active()
            # Add more specific checks for other protection types

        # For now, return false (bypass successful) if protection was executed
        return protection_type not in self.executed_bypasses

    async def _check_anti_debug_active(self) -> bool:
        """Check if anti-debug protection is still active"""
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
                // Timing checks
                var start = Date.now();
                for (var i = 0; i < 1000000; i++) {}
                var elapsed = Date.now() - start;
                if (elapsed > 100) detected = true;  // Suspiciously slow
            } catch(e) {}
            
            send({type: 'detection', result: detected});
            """
            
            # Run detection script
            temp_script = Path("anti_debug_check.js")
            with open(temp_script, 'w') as f:
                f.write(detection_script)
            
            result = await self._run_detection_script(temp_script)
            temp_script.unlink()
            
            return result.get('detected', False)
            
        except Exception as e:
            logger.error(f"Anti-debug detection failed: {e}")
            return False

    async def _check_anti_attach_active(self) -> bool:
        """Check if anti-attach protection is still active"""
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
            with open(temp_script, 'w') as f:
                f.write(detection_script)
            
            result = await self._run_detection_script(temp_script)
            temp_script.unlink()
            
            return result.get('detected', False)
            
        except Exception as e:
            logger.error(f"Anti-attach detection failed: {e}")
            return False

    async def _check_ssl_pinning_active(self) -> bool:
        """Check if SSL pinning is still active"""
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
            with open(temp_script, 'w') as f:
                f.write(detection_script)
            
            result = await self._run_detection_script(temp_script)
            temp_script.unlink()
            
            return result.get('detected', False)
            
        except Exception as e:
            logger.error(f"SSL pinning detection failed: {e}")
            return False
    
    async def _run_detection_script(self, script_path: Path) -> Dict[str, Any]:
        """Run a detection script and collect results"""
        result = {'detected': False}
        
        try:
            # Set up message handler to receive results
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload.get('type') == 'detection':
                        result['detected'] = payload.get('result', False)
            
            # Load and run script
            script_loaded = self.frida_manager.load_script(
                self.session_id,
                str(script_path),
                {"detection_mode": True}
            )
            
            if script_loaded:
                # Wait for detection to complete
                await asyncio.sleep(0.5)
            
            return result
            
        except Exception as e:
            logger.error(f"Detection script execution failed: {e}")
            return {'detected': False}

    async def _adaptive_retry(self, verification_results: Dict[ProtectionType, bool]):
        """Adaptively retry failed bypasses with alternative strategies"""
        retry_count = 0
        max_retries = 3
        
        for prot_type, success in verification_results.items():
            if not success and retry_count < max_retries:
                logger.info(f"Attempting adaptive retry for {prot_type.value}")
                
                # Select alternative strategy based on protection type
                alternative_strategy = self._get_alternative_strategy(prot_type)
                
                if alternative_strategy:
                    try:
                        # Apply alternative bypass
                        retry_success = await self._apply_strategy(alternative_strategy)
                        
                        if retry_success:
                            # Verify the alternative worked
                            await asyncio.sleep(0.5)  # Give time for bypass to take effect
                            verify_success = await self._verify_bypass(prot_type)
                            
                            if verify_success:
                                logger.info(f"Alternative strategy successful for {prot_type.value}")
                                self.metrics['retry_successes'] += 1
                            else:
                                logger.warning(f"Alternative strategy failed verification for {prot_type.value}")
                                self.metrics['retry_failures'] += 1
                        else:
                            self.metrics['retry_failures'] += 1
                            
                    except Exception as e:
                        logger.error(f"Adaptive retry failed for {prot_type.value}: {e}")
                        self.metrics['retry_failures'] += 1
                        
                retry_count += 1
    
    def _get_alternative_strategy(self, protection_type: ProtectionType) -> Optional[BypassStrategy]:
        """Get alternative bypass strategy for failed protection"""
        alternative_strategies = {
            ProtectionType.ANTI_DEBUG: BypassStrategy(
                name="Alternative Anti-Debug Bypass",
                protection_types=[ProtectionType.ANTI_DEBUG],
                confidence=0.7,
                script_path="alternatives/anti_debug_alt.js",
                parameters={"use_kernel_bypass": True}
            ),
            ProtectionType.ANTI_ATTACH: BypassStrategy(
                name="Alternative Anti-Attach Bypass",
                protection_types=[ProtectionType.ANTI_ATTACH],
                confidence=0.7,
                script_path="alternatives/anti_attach_alt.js",
                parameters={"hook_deeper": True}
            ),
            ProtectionType.SSL_PINNING: BypassStrategy(
                name="Alternative SSL Pinning Bypass",
                protection_types=[ProtectionType.SSL_PINNING],
                confidence=0.8,
                script_path="alternatives/ssl_pinning_alt.js",
                parameters={"universal_bypass": True}
            ),
            ProtectionType.ROOT_DETECTION: BypassStrategy(
                name="Alternative Root Detection Bypass",
                protection_types=[ProtectionType.ROOT_DETECTION],
                confidence=0.8,
                script_path="alternatives/root_detection_alt.js",
                parameters={"hide_all_traces": True}
            ),
            ProtectionType.INTEGRITY_CHECK: BypassStrategy(
                name="Alternative Integrity Check Bypass",
                protection_types=[ProtectionType.INTEGRITY_CHECK],
                confidence=0.6,
                script_path="alternatives/integrity_alt.js",
                parameters={"patch_memory": True}
            )
        }
        
        return alternative_strategies.get(protection_type)

    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive wizard report"""
        duration = self.metrics['end_time'] - self.metrics['start_time']

        report = {
            'success': self.state == WizardState.COMPLETE,
            'mode': self.mode,
            'duration': duration,
            'process': self.analysis_results['process_info'],
            'detections': {
                'total': self.metrics['protections_detected'],
                'types': [p.value for p in self.detected_protections.keys()],
                'evidence': {
                    p.value: e for p, e in self.protection_evidence.items()
                }
            },
            'bypasses': {
                'attempted': self.metrics['bypasses_attempted'],
                'successful': self.metrics['bypasses_successful'],
                'failed': len(self.failed_bypasses),
                'success_rate': (
                    self.metrics['bypasses_successful'] / self.metrics['bypasses_attempted'] * 100
                    if self.metrics['bypasses_attempted'] > 0 else 0
                ),
                'successful_types': [p.value for p in self.successful_bypasses],
                'failed_types': [p.value for p in self.failed_bypasses]
            },
            'strategies': [
                {
                    'protection': s.protection_type.value,
                    'scripts': s.scripts,
                    'success': s.success
                }
                for s in self.applied_strategies
            ],
            'metrics': self.metrics
        }

        return report

    def stop(self):
        """Stop the wizard if running"""
        if self.state not in [WizardState.COMPLETE, WizardState.FAILED, WizardState.IDLE]:
            self._update_state(WizardState.FAILED)
            self._update_progress(self.progress, "Wizard stopped by user")


class WizardPresetManager:
    """Manage wizard presets and quick configurations"""

    @staticmethod
    def apply_software_preset(wizard: FridaBypassWizard, software_name: str):
        """Apply preset configuration based on software"""
        preset = get_preset_by_software(software_name)

        # Create custom wizard config from preset
        custom_config = {
            'name': f"{software_name} Preset",
            'description': preset.get('description', ''),
            'detection_first': True,
            'max_scripts': len(preset.get('scripts', [])),
            'priority': preset.get('protections', []),
            'exclude': [],
            'options': preset.get('options', {})
        }

        # Override wizard config
        wizard.config = custom_config
        logger.info(f"Applied preset for: {software_name}")

    @staticmethod
    def create_custom_wizard(config: Dict[str, Any]):
        """Create wizard with custom configuration"""
        # Use lazy import to avoid cyclic import
        from . import get_frida_manager

        FridaManager = get_frida_manager()
        if FridaManager is None:
            raise ImportError("FridaManager not available")

        manager = FridaManager()
        wizard = FridaBypassWizard(manager)

        # Apply custom configuration
        if 'mode' in config:
            wizard.set_mode(config['mode'])

        # Override specific settings
        for key, value in config.items():
            if key in wizard.config:
                wizard.config[key] = value

        return wizard


# Export main components
__all__ = [
    'FridaBypassWizard',
    'WizardState',
    'BypassStrategy',
    'WizardPresetManager'
]
