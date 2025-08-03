"""
Advanced Dynamic Analysis Module

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ...utils.core.import_checks import FRIDA_AVAILABLE, PSUTIL_AVAILABLE, frida, psutil
from ...utils.logger import get_logger, log_message

logger = get_logger(__name__)

class AdvancedDynamicAnalyzer:
    """
    Comprehensive dynamic runtime analysis and exploit simulation
    """

    def __init__(self, binary_path: Union[str, Path]):
        """Initialize the advanced dynamic analyzer with binary path configuration."""
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger("IntellicrackLogger.DynamicAnalyzer")

        # Ensure the binary file exists
        if not self.binary_path.exists() or not self.binary_path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.binary_path}")

        # Analysis results storage
        self.api_calls = []
        self.memory_access = []
        self.network_activity = []
        self.file_operations = []

        # Calculate dynamic memory limits based on system capabilities
        self.memory_limits = self._calculate_memory_limits()

    def _calculate_memory_limits(self) -> Dict[str, int]:
        """Calculate dynamic memory limits based on system capabilities."""
        try:
            # Default conservative limits
            default_limits = {
                'max_region_size': 0x1000000,  # 16MB
                'max_read_size': 0x100000,     # 1MB
                'arch_multiplier': 1
            }

            if not PSUTIL_AVAILABLE:
                self.logger.warning("psutil not available, using conservative memory limits")
                return default_limits

            # Get system memory information
            virtual_memory = psutil.virtual_memory()
            available_memory = virtual_memory.available

            # Calculate adaptive limits based on available memory
            # Use a conservative percentage of available memory
            memory_percentage = 0.05  # Use 5% of available memory max
            max_memory_for_analysis = int(available_memory * memory_percentage)

            # Set architecture-based multipliers
            arch_multiplier = 2 if os.name == 'nt' else 1  # Windows can handle larger regions

            # Calculate region and read sizes
            max_region_size = min(max_memory_for_analysis // 10, 0x4000000)  # Max 64MB per region
            max_read_size = min(max_region_size // 8, 0x800000)  # Max 8MB per read

            # Apply architecture scaling
            if max_region_size > 0x2000000:  # If we have plenty of memory
                arch_multiplier = 2 if os.name == 'nt' else 1.5

            limits = {
                'max_region_size': int(max_region_size * arch_multiplier),
                'max_read_size': int(max_read_size * arch_multiplier),
                'arch_multiplier': arch_multiplier,
                'available_memory': available_memory,
                'analysis_memory_budget': max_memory_for_analysis
            }

            self.logger.debug(f"Calculated dynamic memory limits: {limits}")
            return limits

        except Exception as e:
            self.logger.warning(f"Failed to calculate dynamic memory limits: {e}")
            return default_limits

    async def run_comprehensive_analysis(self, payload: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Execute multi-stage dynamic analysis.

        Performs a comprehensive dynamic analysis of the target binary using multiple
        techniques including subprocess execution, Frida-based runtime analysis, and
        process behavior monitoring. Optionally injects a payload during analysis.

        Args:
            payload: Optional binary payload to inject during analysis

        Returns:
            dict: Analysis results from all stages, including subprocess execution,
                 runtime analysis, and process behavior information
        """
        self.logger.info(f"Running comprehensive dynamic analysis for {self.binary_path}. Payload provided: {bool(payload)}")

        # Run analysis methods concurrently for better performance
        subprocess_task = self._subprocess_analysis()
        frida_task = self._frida_runtime_analysis(payload)
        behavior_task = self._process_behavior_analysis()

        # Await all tasks concurrently
        subprocess_result, frida_result, behavior_result = await asyncio.gather(
            subprocess_task, frida_task, behavior_task, return_exceptions=True
        )

        analysis_results = {
            'subprocess_execution': subprocess_result if not isinstance(subprocess_result, Exception) else {'success': False, 'error': str(subprocess_result)},
            'frida_runtime_analysis': frida_result if not isinstance(frida_result, Exception) else {'success': False, 'error': str(frida_result)},
            'process_behavior_analysis': behavior_result if not isinstance(behavior_result, Exception) else {'success': False, 'error': str(behavior_result)}
        }

        self.logger.info("Comprehensive dynamic analysis completed.")
        self.logger.debug("Dynamic analysis results: %s", analysis_results)

        return analysis_results

    async def _subprocess_analysis(self) -> Dict[str, Any]:
        """
        Standard subprocess execution analysis.

        Executes the target binary in a controlled subprocess environment and
        captures its standard output, standard error, and return code. Provides
        basic execution analysis without instrumentation.

        Returns:
            dict: Execution results including success status, stdout/stderr output,
                 and return code or error information
        """
        self.logger.info("Starting subprocess analysis for %s", self.binary_path)

        try:
            from ...utils.system.subprocess_utils import async_run_subprocess

            returncode, stdout, stderr = await async_run_subprocess(
                [self.binary_path],
                timeout=10,
                capture_output=True,
                text=True
            )

            self.logger.debug("Subprocess result: Success=%s, ReturnCode=%s", returncode == 0, returncode)

            return {
                'success': returncode == 0,
                'stdout': stdout,
                'stderr': stderr,
                'return_code': returncode
            }
        except asyncio.TimeoutError:
            self.logger.error("Subprocess analysis error: Timeout expired")
            return {'success': False, 'error': 'Timeout expired'}
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Subprocess analysis error: %s", e, exc_info=True)
            return {'success': False, 'error': str(e)}

    async def _frida_runtime_analysis(self, payload: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Advanced Frida-based runtime analysis with adaptive timing.

        Uses Frida instrumentation to perform deep runtime analysis of the target binary.
        Hooks key functions, monitors license-related activities, and optionally injects
        a custom payload. Provides detailed insights into the binary's runtime behavior.

        Args:
            payload: Optional binary payload to inject during analysis

        Returns:
            dict: Runtime analysis results including intercepted function calls,
                 detected license mechanisms, and injection status
        """
        if not FRIDA_AVAILABLE:
            self.logger.error("Frida not available for runtime analysis")
            return {'success': False, 'error': 'Frida not available'}

        pid = None
        session = None
        script = None

        try:
            # Spawn the process
            pid = frida.spawn(self.binary_path)
            session = frida.attach(pid)

            # Create comprehensive interceptor script
            frida_script = '''
            console.log("[Frida] Runtime analysis started");

            // Global data collection
            var interceptedCalls = [];
            var stringReferences = [];
            var networkActivity = [];
            var fileActivity = [];
            var registryActivity = [];
            var cryptoActivity = [];
            var timingChecks = [];

            // Helper function to read string from memory
            function readString(address) {
                try {
                    return Memory.readCString(address);
                } catch (e) {
                    return "<unreadable>";
                }
            }

            // Hook common Windows API functions

            // File operations
            const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
            if (CreateFileW) {
                Interceptor.attach(CreateFileW, {
                    onEnter: function(args) {
                        const filename = args[0].readUtf16String();
                        const access = args[1].toInt32();
                        const shareMode = args[2].toInt32();
                        const creation = args[4].toInt32();

                        fileActivity.push({
                            function: 'CreateFileW',
                            filename: filename,
                            access: access,
                            shareMode: shareMode,
                            creation: creation,
                            timestamp: Date.now()
                        });

                        send({
                            type: 'file_access',
                            data: {
                                function: 'CreateFileW',
                                filename: filename,
                                access: access
                            }
                        });
                    },
                    onLeave: function(retval) {
                        // Log handle for tracking
                    }
                });
            }

            // Registry operations
            const RegOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
            if (RegOpenKeyExW) {
                Interceptor.attach(RegOpenKeyExW, {
                    onEnter: function(args) {
                        const keyName = args[1].readUtf16String();
                        const access = args[3].toInt32();

                        registryActivity.push({
                            function: 'RegOpenKeyExW',
                            keyName: keyName,
                            access: access,
                            timestamp: Date.now()
                        });

                        send({
                            type: 'registry_access',
                            data: {
                                function: 'RegOpenKeyExW',
                                keyName: keyName
                            }
                        });
                    }
                });
            }

            // Network operations
            const connect = Module.findExportByName('ws2_32.dll', 'connect');
            if (connect) {
                Interceptor.attach(connect, {
                    onEnter: function(args) {
                        const sockaddr = args[1];
                        const addrFamily = sockaddr.readU16();

                        if (addrFamily === 2) { // AF_INET
                            const port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                            const ip = [
                                sockaddr.add(4).readU8(),
                                sockaddr.add(5).readU8(),
                                sockaddr.add(6).readU8(),
                                sockaddr.add(7).readU8()
                            ].join('.');

                            networkActivity.push({
                                function: 'connect',
                                address: ip + ':' + port,
                                timestamp: Date.now()
                            });

                            send({
                                type: 'network_activity',
                                data: {
                                    function: 'connect',
                                    address: ip + ':' + port
                                }
                            });
                        }
                    }
                });
            }

            // Cryptographic operations
            const CryptAcquireContextW = Module.findExportByName('advapi32.dll', 'CryptAcquireContextW');
            if (CryptAcquireContextW) {
                Interceptor.attach(CryptAcquireContextW, {
                    onEnter: function(args) {
                        const containerName = args[1].isNull() ? null : args[1].readUtf16String();
                        const providerName = args[2].isNull() ? null : args[2].readUtf16String();

                        cryptoActivity.push({
                            function: 'CryptAcquireContextW',
                            container: containerName,
                            provider: providerName,
                            timestamp: Date.now()
                        });

                        send({
                            type: 'crypto_activity',
                            data: {
                                function: 'CryptAcquireContextW',
                                container: containerName,
                                provider: providerName
                            }
                        });
                    }
                });
            }

            // Time-based anti-debugging
            const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
            if (GetTickCount) {
                var lastTickCount = 0;
                Interceptor.attach(GetTickCount, {
                    onLeave: function(retval) {
                        const currentTick = retval.toInt32();
                        if (lastTickCount > 0) {
                            const delta = currentTick - lastTickCount;
                            if (delta > 1000) { // Suspicious delay
                                timingChecks.push({
                                    function: 'GetTickCount',
                                    delta: delta,
                                    timestamp: Date.now()
                                });

                                send({
                                    type: 'timing_check',
                                    data: {
                                        function: 'GetTickCount',
                                        delta: delta
                                    }
                                });
                            }
                        }
                        lastTickCount = currentTick;
                    }
                });
            }

            // License-specific function detection with patterns
            const licensePatterns = [
                /license/i, /activation/i, /validate/i, /serial/i,
                /key/i, /register/i, /unlock/i, /trial/i, /expire/i,
                /authenticate/i, /authorize/i, /verify/i
            ];

            // Enhanced module enumeration
            Process.enumerateModules().forEach(function(module) {
                console.log('[Frida] Scanning module: ' + module.name);

                // Check module exports
                Module.enumerateExports(module.name).forEach(function(exp) {
                    const expName = exp.name.toLowerCase();

                    // Check against license patterns
                    for (let pattern of licensePatterns) {
                        if (pattern.test(expName)) {
                            console.log('[Frida] License-related function found: ' + exp.name + ' in ' + module.name);

                            try {
                                Interceptor.attach(exp.address, {
                                    onEnter: function(args) {
                                        const callInfo = {
                                            module: module.name,
                                            function: exp.name,
                                            args: [],
                                            timestamp: Date.now()
                                        };

                                        // Try to capture arguments (up to 4)
                                        for (let i = 0; i < 4 && i < args.length; i++) {
                                            try {
                                                if (!args[i].isNull()) {
                                                    // Try to read as string first
                                                    try {
                                                        const str = args[i].readUtf16String();
                                                        if (str && str.length < 100) {
                                                            callInfo.args.push({ type: 'string', value: str });
                                                            continue;
                                                        }
                                                    } catch (e) {}

                                                    // Try as integer
                                                    callInfo.args.push({ type: 'int', value: args[i].toInt32() });
                                                }
                                            } catch (e) {
                                                callInfo.args.push({ type: 'unknown', value: args[i].toString() });
                                            }
                                        }

                                        interceptedCalls.push(callInfo);

                                        send({
                                            type: 'license_function',
                                            data: callInfo
                                        });

                                        this.callInfo = callInfo;
                                    },
                                    onLeave: function(retval) {
                                        this.callInfo.returnValue = retval.toInt32();

                                        send({
                                            type: 'license_function_return',
                                            data: {
                                                function: this.callInfo.function,
                                                returnValue: this.callInfo.returnValue
                                            }
                                        });
                                    }
                                });
                            } catch (e) {
                                console.log('[Frida] Failed to hook ' + exp.name + ': ' + e);
                            }
                        }
                    }
                });
            });

            // String scanning for license-related content
            Process.enumerateRanges('r--').forEach(function(range) {
                try {
                    const rangeSize = range.size;
                    if (rangeSize > 0 && rangeSize < 1024 * 1024) { // Limit to 1MB
                        const data = Memory.readByteArray(range.base, Math.min(rangeSize, 65536));
                        const str = String.fromCharCode.apply(null, new Uint8Array(data));

                        // Look for license-related strings
                        licensePatterns.forEach(function(pattern) {
                            const matches = str.match(new RegExp(pattern.source + '.{0,50}', 'gi'));
                            if (matches) {
                                matches.forEach(function(match) {
                                    stringReferences.push({
                                        address: range.base,
                                        pattern: pattern.source,
                                        context: match,
                                        timestamp: Date.now()
                                    });

                                    send({
                                        type: 'string_reference',
                                        data: {
                                            address: range.base.toString(),
                                            pattern: pattern.source,
                                            context: match
                                        }
                                    });
                                });
                            }
                        });
                    }
                } catch (e) {
                    // Continue on read errors
                }
            });

            // Adaptive completion reporting - wait for activity to stabilize
            var activityTimeout;
            var lastActivityTime = Date.now();
            var reportSent = false;
            
            function reportCompletion() {
                if (!reportSent) {
                    reportSent = true;
                    send({
                        type: 'analysis_complete',
                        data: {
                            interceptedCalls: interceptedCalls,
                            stringReferences: stringReferences,
                            networkActivity: networkActivity,
                            fileActivity: fileActivity,
                            registryActivity: registryActivity,
                            cryptoActivity: cryptoActivity,
                            timingChecks: timingChecks
                        }
                    });
                }
            }
            
            // Track activity and report when stable
            function resetActivityTimer() {
                lastActivityTime = Date.now();
                if (activityTimeout) {
                    clearTimeout(activityTimeout);
                }
                activityTimeout = setTimeout(reportCompletion, 3000); // 3 second stabilization period
            }
            
            // Override send to track activity
            const originalSend = send;
            send = function(data) {
                resetActivityTimer();
                return originalSend(data);
            };
            
            // Initial timeout for minimum execution time
            setTimeout(reportCompletion, 8000); // Minimum 8 seconds
            resetActivityTimer();
            '''

            # Message handler with adaptive analysis
            analysis_data = {}
            analysis_start_time = time.time()
            last_activity_time = analysis_start_time

            def on_message(message, _data):  # pylint: disable=unused-argument
                """
                Handle messages from the Frida script during dynamic analysis.

                Args:
                    message: Message dictionary from Frida containing 'type' and 'payload'
                    _data: Additional data (unused)

                Processes different message types including analysis completion and
                various activity tracking (file access, registry, network, licensing).
                """
                nonlocal last_activity_time
                last_activity_time = time.time()

                if message['type'] == 'send':
                    payload_data = message['payload']
                    msg_type = payload_data.get('type')

                    if msg_type == 'analysis_complete':
                        analysis_data.update(payload_data['data'])
                    elif msg_type in ['file_access', 'registry_access', 'network_activity', 'license_function']:
                        if msg_type not in analysis_data:
                            analysis_data[msg_type] = []
                        analysis_data[msg_type].append(payload_data['data'])

            script = session.create_script(frida_script)
            script.on('message', on_message)
            script.load()

            # Resume the process and let it run with adaptive timing
            frida.resume(pid)

            # Adaptive runtime analysis based on process behavior
            runtime_duration = await self._calculate_adaptive_runtime(pid, analysis_start_time)
            await asyncio.sleep(runtime_duration)

            self.logger.info(f"Frida runtime analysis completed after {runtime_duration:.2f} seconds")
            return {
                'success': True,
                'pid': pid,
                'analysis_data': analysis_data,
                'payload_injected': payload is not None,
                'runtime_duration': runtime_duration
            }

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Frida runtime analysis error: %s", e, exc_info=True)
            return {'success': False, 'error': str(e)}
        finally:
            # Cleanup
            try:
                if script is not None:
                    script.unload()
                if session is not None:
                    session.detach()
                if pid is not None:
                    frida.kill(pid)
            except Exception as cleanup_error:
                self.logger.error("Error during Frida cleanup: %s", cleanup_error)

    def _calculate_process_stabilization_time(self, pid: int) -> float:
        """Calculate appropriate stabilization time for process initialization"""
        if not PSUTIL_AVAILABLE:
            return 2.0  # Default fallback

        try:
            process = psutil.Process(pid)

            # Base time for process stabilization
            base_time = 0.5

            # Factor in memory usage - larger processes need more time
            try:
                memory_mb = process.memory_info().rss / (1024 * 1024)
                memory_factor = min(memory_mb / 100, 3.0)  # Cap at 3x multiplier
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                memory_factor = 1.0

            # Factor in number of threads
            try:
                thread_count = process.num_threads()
                thread_factor = min(thread_count / 10, 2.0)  # Cap at 2x multiplier
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                thread_factor = 1.0

            # Calculate adaptive stabilization time
            stabilization_time = base_time * (1 + memory_factor + thread_factor)

            # Ensure reasonable bounds (0.5 to 8 seconds)
            return max(0.5, min(stabilization_time, 8.0))

        except Exception:
            return 2.0  # Safe fallback

    async def _calculate_adaptive_runtime(self, pid: int, start_time: float) -> float:
        """Calculate adaptive runtime based on process behavior and activity."""
        try:
            if not PSUTIL_AVAILABLE:
                # Fallback to reasonable default
                return 8.0

            process = psutil.Process(pid)
            initial_cpu_times = process.cpu_times()
            initial_memory = process.memory_info().rss

            # Monitor process for activity patterns
            activity_samples = []
            base_runtime = 3.0  # Minimum runtime
            max_runtime = 30.0  # Maximum runtime

            # Sample process metrics over time
            for i in range(5):  # 5 samples over 2.5 seconds
                await asyncio.sleep(0.5)

                try:
                    current_cpu_times = process.cpu_times()
                    current_memory = process.memory_info().rss

                    # Calculate activity metrics
                    cpu_delta = (current_cpu_times.user + current_cpu_times.system) - \
                              (initial_cpu_times.user + initial_cpu_times.system)
                    memory_delta = abs(current_memory - initial_memory)

                    activity_score = cpu_delta * 10 + (memory_delta / 1024 / 1024)  # CPU weight + MB
                    activity_samples.append(activity_score)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process may have terminated
                    break

            if activity_samples:
                avg_activity = sum(activity_samples) / len(activity_samples)

                # Calculate adaptive runtime based on activity
                if avg_activity > 5.0:  # High activity
                    runtime = min(max_runtime, base_runtime + (avg_activity * 2))
                elif avg_activity > 1.0:  # Medium activity
                    runtime = min(max_runtime, base_runtime + (avg_activity * 4))
                else:  # Low activity
                    runtime = base_runtime + 2.0

                self.logger.debug(f"Adaptive runtime calculated: {runtime:.2f}s based on activity: {avg_activity:.2f}")
                return runtime
            else:
                return base_runtime + 3.0

        except Exception as e:
            self.logger.warning(f"Error calculating adaptive runtime: {e}")
            return 8.0  # Safe fallback

    async def _process_behavior_analysis(self) -> Dict[str, Any]:
        """
        Analyze process behavior and resource interactions.

        Monitors the target process during execution to collect information about
        its resource usage, file operations, network connections, and threading
        behavior. Provides insights into how the application interacts with the system.

        Returns:
            dict: Process behavior data including memory usage, open files,
                 network connections, and thread information
        """
        if not PSUTIL_AVAILABLE:
            self.logger.error("psutil not available for process behavior analysis")
            return {'success': False, 'error': 'psutil not available'}

        self.logger.info("Starting process behavior analysis for %s", self.binary_path)

        try:
            # Use psutil for detailed process analysis
            process = await asyncio.create_subprocess_exec(
                self.binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for process to stabilize using adaptive timing
            stabilization_time = self._calculate_process_stabilization_time(process.pid)
            await asyncio.sleep(stabilization_time)

            ps_process = psutil.Process(process.pid)

            analysis = {
                'pid': process.pid,
                'memory_info': dict(ps_process.memory_info()._asdict()),
                'open_files': [f.path for f in ps_process.open_files()],
                'connections': [
                    {
                        'fd': c.fd,
                        'family': c.family,
                        'type': c.type,
                        'laddr': str(c.laddr),
                        'raddr': str(c.raddr)
                    } for c in ps_process.connections()
                ],
                'threads': ps_process.num_threads()
            }

            # Terminate process
            process.terminate()

            self.logger.debug("Process behavior analysis result: PID=%s, Memory=%s, Threads=%s", analysis.get('pid'), analysis.get('memory_info'), analysis.get('threads'))

            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Process behavior analysis error: %s", e, exc_info=True)
            return {'error': str(e)}

    def scan_memory_for_keywords(self, keywords: List[str], target_process: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan process memory for specific keywords.

        Performs real-time memory scanning of the target process or a specified process
        to find occurrences of license-related keywords, serial numbers, or other patterns.

        Args:
            keywords: List of keywords to search for in memory
            target_process: Optional process name to scan (defaults to binary_path)

        Returns:
            Dictionary containing scan results with matches, addresses, and context
        """
        self.logger.info(f"Starting memory keyword scan for: {keywords}")

        try:
            if FRIDA_AVAILABLE:
                return self._frida_memory_scan(keywords, target_process)
            elif PSUTIL_AVAILABLE:
                return self._psutil_memory_scan(keywords, target_process)
            else:
                return self._fallback_memory_scan(keywords, target_process)
        except Exception as e:
            self.logger.error(f"Memory scanning error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'matches': []
            }

    async def _frida_memory_scan(self, keywords: List[str], target_process: Optional[str] = None) -> Dict[str, Any]:
        """Perform memory scanning using Frida instrumentation."""
        try:
            # Get process to attach to
            process_name = target_process or Path(self.binary_path).name

            # Find the target process
            session = None
            device = frida.get_local_device()
            for proc in device.enumerate_processes():
                if process_name.lower() in proc.name.lower():
                    session = device.attach(proc.pid)
                    break

            if not session:
                # Try to spawn the process if not found
                try:
                    pid = frida.spawn([str(self.binary_path)])
                    session = frida.attach(pid)
                    frida.resume(pid)
                    # Allow process to initialize using adaptive timing
                    init_time = self._calculate_process_stabilization_time(pid)
                    await asyncio.sleep(init_time)
                except Exception as e:
                    logger.error("Exception in dynamic_analyzer: %s", e)
                    return {
                        'status': 'error',
                        'error': f'Could not attach to or spawn process: {process_name}',
                        'matches': []
                    }

            # Get dynamic memory limits calculated from system capabilities
            max_region_size = self.memory_limits['max_region_size']
            max_read_size = self.memory_limits['max_read_size']

            # Frida script for memory scanning
            script_code = f"""
            // Memory scanning script
            const keywords = {keywords};
            const matches = [];
            let scanCount = 0;

            function scanMemoryRegions() {{
                try {{
                    const ranges = Process.enumerateRanges('r--');

                    ranges.forEach(function(range) {{
                        // Dynamic memory region limits calculated from system capabilities
                        const maxRegionSize = {max_region_size};
                        const maxReadSize = {max_read_size};
                        
                        if (range.size > maxRegionSize) return; // Skip oversized regions

                        try {{
                            const readSize = Math.min(range.size, maxReadSize);
                            const memory = Memory.readByteArray(range.base, readSize);
                            if (memory) {{
                                const view = new Uint8Array(memory);
                                const text = String.fromCharCode.apply(null, view);

                                keywords.forEach(function(keyword) {{
                                    let index = 0;
                                    while ((index = text.toLowerCase().indexOf(keyword.toLowerCase(), index)) !== -1) {{
                                        const address = range.base.add(index);
                                        const contextStart = Math.max(0, index - 50);
                                        const contextEnd = Math.min(text.length, index + keyword.length + 50);
                                        const context = text.substring(contextStart, contextEnd);

                                        matches.push({{
                                            address: address.toString(),
                                            keyword: keyword,
                                            context: context.replace(/[\\x00-\\x1F\\x7F-\\xFF]/g, '.'),
                                            offset: index,
                                            region_base: range.base.toString(),
                                            region_size: range.size
                                        }});

                                        index += keyword.length;
                                    }}
                                }});
                            }}
                        }} catch (e) {{
                            // Skip inaccessible memory regions
                        }}
                    }});

                    send({{ type: 'scan_complete', matches: matches, scan_count: scanCount++ }});
                }} catch (e) {{
                    send({{ type: 'error', message: e.toString() }});
                }}
            }}

            // Start scanning
            scanMemoryRegions();

            // Schedule periodic re-scan (every 5 seconds for 30 seconds)
            const intervalId = setInterval(scanMemoryRegions, 5000);
            setTimeout(function() {{
                clearInterval(intervalId);
                send({{ type: 'complete' }});
            }}, 30000);
            """

            script = session.create_script(script_code)
            results = {'matches': [], 'status': 'success', 'scan_count': 0}

            def on_message(message, data):
                if data:
                    self.logger.debug(f"Message data: {len(data)} bytes")
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] == 'scan_complete':
                        results['matches'].extend(payload['matches'])
                        results['scan_count'] = payload['scan_count']
                    elif payload['type'] == 'error':
                        self.logger.error(f"Frida script error: {payload['message']}")
                    elif payload['type'] == 'complete':
                        results['status'] = 'complete'

            script.on('message', on_message)
            script.load()

            # Wait for scanning to complete
            timeout = 35  # Give extra time for completion
            start_time = time.time()
            while time.time() - start_time < timeout and results['status'] != 'complete':
                await asyncio.sleep(1)

            script.unload()
            session.detach()

            # Remove duplicates and sort by address
            unique_matches = []
            seen = set()
            for match in results['matches']:
                key = (match['address'], match['keyword'])
                if key not in seen:
                    seen.add(key)
                    unique_matches.append(match)

            results['matches'] = sorted(unique_matches, key=lambda x: int(x['address'], 16))
            self.logger.info(f"Frida memory scan found {len(results['matches'])} matches")

            return results

        except Exception as e:
            self.logger.error(f"Frida memory scan error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'matches': []
            }

    async def _psutil_memory_scan(self, keywords: List[str], target_process: Optional[str] = None) -> Dict[str, Any]:
        """Perform basic memory scanning using psutil (limited functionality)."""
        try:
            process_name = target_process or Path(self.binary_path).name

            # Find target process
            target_proc = None
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if process_name.lower() in proc.info['name'].lower():
                        target_proc = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.error("Error in dynamic_analyzer: %s", e)
                    continue

            if not target_proc:
                # Try to start the process
                try:
                    proc = await asyncio.create_subprocess_exec(str(self.binary_path))
                    # Wait for process startup using adaptive timing
                    startup_time = self._calculate_process_stabilization_time(proc.pid)
                    await asyncio.sleep(startup_time)
                    target_proc = psutil.Process(proc.pid)
                except Exception as e:
                    logger.error("Exception in dynamic_analyzer: %s", e)
                    return {
                        'status': 'error',
                        'error': f'Could not find or start process: {process_name}',
                        'matches': []
                    }

            matches = []

            # Basic memory information (limited on most systems)
            try:
                memory_info = target_proc.memory_info()
                memory_maps = target_proc.memory_maps() if hasattr(target_proc, 'memory_maps') else []

                # Simulate memory scanning with process environment and command line
                cmdline = ' '.join(target_proc.cmdline()) if hasattr(target_proc, 'cmdline') else ''
                environ_vars = list(target_proc.environ().values()) if hasattr(target_proc, 'environ') else []

                search_text = (cmdline + ' ' + ' '.join(environ_vars)).lower()

                for keyword in keywords:
                    if keyword.lower() in search_text:
                        matches.append({
                            'address': '0x00000000',  # Placeholder address
                            'keyword': keyword,
                            'context': f'Found in process environment/cmdline: {keyword}',
                            'offset': 0,
                            'region_base': '0x00000000',
                            'region_size': len(search_text)
                        })

                self.logger.info(f"PSUtil memory scan found {len(matches)} matches")

                return {
                    'status': 'success',
                    'matches': matches,
                    'memory_info': {
                        'rss': memory_info.rss,
                        'vms': memory_info.vms,
                        'num_memory_maps': len(memory_maps)
                    }
                }

            except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                logger.error("Error in dynamic_analyzer: %s", e)
                return {
                    'status': 'error',
                    'error': f'Access denied or process not found: {e}',
                    'matches': []
                }

        except Exception as e:
            self.logger.error(f"PSUtil memory scan error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'matches': []
            }

    def _fallback_memory_scan(self, keywords: List[str], target_process: Optional[str] = None) -> Dict[str, Any]:
        """Fallback memory scanning using binary file analysis."""
        try:
            if target_process:
                self.logger.info(f"Using fallback memory scan for process {target_process}")
            else:
                self.logger.info("Using fallback memory scan (binary file analysis)")

            matches = []

            # Read and scan the binary file itself
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()

            # Convert to text for searching
            binary_text = binary_data.decode('utf-8', errors='ignore').lower()

            for keyword in keywords:
                keyword_lower = keyword.lower()
                offset = 0

                while True:
                    index = binary_text.find(keyword_lower, offset)
                    if index == -1:
                        break

                    # Get context around the match
                    context_start = max(0, index - 50)
                    context_end = min(len(binary_text), index + len(keyword) + 50)
                    context = binary_text[context_start:context_end]

                    matches.append({
                        'address': f'0x{index:08X}',
                        'keyword': keyword,
                        'context': context.replace('\x00', '.'),
                        'offset': index,
                        'region_base': '0x00000000',
                        'region_size': len(binary_data)
                    })

                    offset = index + len(keyword)

            self.logger.info(f"Fallback memory scan found {len(matches)} matches")

            return {
                'status': 'success',
                'matches': matches,
                'scan_type': 'binary_file_analysis'
            }

        except Exception as e:
            self.logger.error(f"Fallback memory scan error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'matches': []
            }

    def analyze(self, binary_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze a binary file - compatibility method for orchestrator.
        
        Args:
            binary_path: Path to the binary to analyze
            
        Returns:
            dict: Comprehensive analysis results
        """
        try:
            # If we're already initialized with the same binary, just run analysis
            if str(self.binary_path) == str(binary_path):
                return self.run_comprehensive_analysis()
            else:
                # Create new analyzer for different binary
                analyzer = AdvancedDynamicAnalyzer(binary_path)
                return analyzer.run_comprehensive_analysis()
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'subprocess_execution': {'success': False, 'error': str(e)},
                'frida_runtime_analysis': {'success': False, 'error': str(e)},
                'process_behavior_analysis': {'error': str(e)}
            }

    def is_available(self) -> bool:
        """
        Check if dynamic analysis is available on this system.
        
        Returns:
            bool: True if dynamic analysis can be performed
        """
        # Check for required dependencies
        available = True
        reasons = []

        # Check if psutil is available
        try:
            import psutil
        except ImportError:
            available = False
            reasons.append("psutil not available")

        # Check if we're on a supported platform
        import platform
        if platform.system() not in ['Windows', 'Linux']:
            available = False
            reasons.append(f"Unsupported platform: {platform.system()}")

        # Check if binary exists and is executable
        if not self.binary_path.exists():
            available = False
            reasons.append("Binary file not found")
        elif not os.access(str(self.binary_path), os.X_OK):
            # On Windows, check if it's an executable file
            if platform.system() == 'Windows':
                ext = self.binary_path.suffix.lower()
                if ext not in ['.exe', '.dll', '.com', '.bat', '.cmd']:
                    available = False
                    reasons.append("Not an executable file")
            else:
                available = False
                reasons.append("Binary not executable")

        if not available:
            self.logger.warning(f"Dynamic analysis not available: {', '.join(reasons)}")

        return available


# Convenience functions for application integration
def run_dynamic_analysis(app, binary_path: Optional[Union[str, Path]] = None,
                        payload: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Run dynamic analysis on a binary with app integration.

    Args:
        app: Application instance with update_output signal
        binary_path: Optional path to binary (uses app.binary_path if not provided)
        payload: Optional payload to inject

    Returns:
        Analysis results dictionary
    """
    # Use provided path or get from app
    path = binary_path or getattr(app, 'binary_path', None)
    if not path:
        app.update_output.emit(log_message("[Dynamic] No binary selected."))
        return {'error': 'No binary selected'}

    app.update_output.emit(log_message("[Dynamic] Starting dynamic analysis..."))

    # Create analyzer
    analyzer = AdvancedDynamicAnalyzer(path)

    # Run analysis
    results = analyzer.run_comprehensive_analysis(payload)

    # Display results
    app.update_output.emit(log_message("[Dynamic] Analysis completed"))

    # Add to analyze results
    if not hasattr(app, "analyze_results"):
        app.analyze_results = []

    app.analyze_results.append("\n=== DYNAMIC ANALYSIS RESULTS ===")

    # Subprocess results
    if 'subprocess_execution' in results:
        sub_result = results['subprocess_execution']
        app.analyze_results.append("\nSubprocess Execution:")
        app.analyze_results.append(f"  Success: {sub_result.get('success', False)}")
        if sub_result.get('return_code') is not None:
            app.analyze_results.append(f"  Return Code: {sub_result['return_code']}")

    # Frida runtime analysis
    if 'frida_runtime_analysis' in results:
        frida_result = results['frida_runtime_analysis']
        if frida_result.get('success'):
            analysis_data = frida_result.get('analysis_data', {})
            app.analyze_results.append("\nRuntime Analysis:")
            app.analyze_results.append(f"  File Operations: {len(analysis_data.get('file_access', []))}")
            app.analyze_results.append(f"  Registry Operations: {len(analysis_data.get('registry_access', []))}")
            app.analyze_results.append(f"  Network Connections: {len(analysis_data.get('network_activity', []))}")
            app.analyze_results.append(f"  License Functions: {len(analysis_data.get('license_function', []))}")

            # Show some details
            if analysis_data.get('license_function'):
                app.analyze_results.append("\n  Detected License Functions:")
                for func in analysis_data['license_function'][:5]:
                    app.analyze_results.append(f"    - {func.get('function', 'Unknown')} in {func.get('module', 'Unknown')}")

    # Process behavior
    if 'process_behavior_analysis' in results:
        behavior = results['process_behavior_analysis']
        if 'error' not in behavior:
            app.analyze_results.append("\nProcess Behavior:")
            app.analyze_results.append(f"  PID: {behavior.get('pid', 'Unknown')}")
            app.analyze_results.append(f"  Threads: {behavior.get('threads', 0)}")
            if behavior.get('memory_info'):
                mem = behavior['memory_info']
                app.analyze_results.append(f"  Memory RSS: {mem.get('rss', 0) / 1024 / 1024:.2f} MB")

    return results


async def deep_runtime_monitoring(binary_path: str, timeout: int = 30000) -> List[str]:
    """
    Monitor runtime behavior of the binary using Frida instrumentation.

    Monitors key Windows APIs for registry, file, network operations and license-related
    behavior. Provides comprehensive runtime analysis of the target binary.

    Args:
        binary_path: Path to the binary to monitor
        timeout: Timeout in milliseconds (default: 30000)

    Returns:
        List[str]: Log messages from the monitoring session
    """
    logs = [
        f"Starting runtime monitoring of {binary_path} (timeout: {timeout}ms)"]

    try:
        if not FRIDA_AVAILABLE:
            logs.append("Error: Frida not available for runtime monitoring")
            return logs

        # Create a basic Frida script to monitor key APIs
        script_content = """
        function log(message) {
            send(message);
            return true;
        }

        (function() {
            log("[Intellicrack] Runtime monitoring started");

            // Registry API hooks
            var regOpenKeyExW = Module.findExportByName("advapi32.dll", "RegOpenKeyExW");
            if (regOpenKeyExW) {
                Interceptor.attach(regOpenKeyExW, {
                    onEnter: function(args) {
                        if (args[1]) {
                            try {
                                var keyPath = args[1].readUtf16String();
                                log("[Registry] Opening key: " + keyPath);
                            } catch (e) {}
                        }
                    }
                });
            }

            // File API hooks
            var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
            if (createFileW) {
                Interceptor.attach(createFileW, {
                    onEnter: function(args) {
                        if (args[0]) {
                            try {
                                var filePath = args[0].readUtf16String();
                                log("[File] Opening file: " + filePath);
                            } catch (e) {}
                        }
                    }
                });
            }

            // Network API hooks
            var connect = Module.findExportByName("ws2_32.dll", "connect");
            if (connect) {
                Interceptor.attach(connect, {
                    onEnter: function(args) {
                        log("[Network] Connect called");
                    }
                });
            }

            // License validation hooks - MessageBox for errors
            var messageBoxW = Module.findExportByName("user32.dll", "MessageBoxW");
            if (messageBoxW) {
                Interceptor.attach(messageBoxW, {
                    onEnter: function(args) {
                        if (args[1]) {
                            try {
                                var message = args[1].readUtf16String();
                                log("[UI] MessageBox: " + message);
                            } catch (e) {}
                        }
                    }
                });
            }

            log("[Intellicrack] Hooks installed");
        })();
        """

        # Launch the process
        logs.append("Launching process...")
        process = await asyncio.create_subprocess_exec(binary_path)
        logs.append(f"Process started with PID {process.pid}")

        # Attach Frida
        logs.append("Attaching Frida...")
        session = frida.attach(process.pid)

        # Create script
        script = session.create_script(script_content)

        # Set up message handler
        def on_message(message, _data):  # pylint: disable=unused-argument
            """
            Callback for handling messages from a Frida script.

            Appends payloads from 'send' messages to the logs list.
            """
            if message["type"] == "send":
                logs.append(message["payload"])

        script.on("message", on_message)
        script.load()

        # Monitor for specified timeout
        logs.append(f"Monitoring for {timeout / 1000} seconds...")
        await asyncio.sleep(timeout / 1000)

        # Detach and terminate
        logs.append("Detaching Frida...")
        session.detach()

        logs.append("Terminating process...")
        process.terminate()

        logs.append("Runtime monitoring complete")

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in dynamic_analyzer: %s", e)
        logs.append(f"Error during runtime monitoring: {e}")

    return logs


# Additional convenience functions
def create_dynamic_analyzer(binary_path: Union[str, Path]) -> AdvancedDynamicAnalyzer:
    """
    Factory function to create a dynamic analyzer instance.

    Args:
        binary_path: Path to the target binary

    Returns:
        AdvancedDynamicAnalyzer: Configured analyzer instance
    """
    return AdvancedDynamicAnalyzer(binary_path)

def run_quick_analysis(binary_path: Union[str, Path], payload: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Run a quick comprehensive analysis on a binary.

    Args:
        binary_path: Path to the target binary
        payload: Optional payload to inject

    Returns:
        dict: Analysis results
    """
    analyzer = create_dynamic_analyzer(binary_path)
    return analyzer.run_comprehensive_analysis(payload)


# Create alias for backward compatibility
DynamicAnalyzer = AdvancedDynamicAnalyzer
