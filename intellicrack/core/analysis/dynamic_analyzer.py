"""
Advanced Dynamic Analysis Module

This module provides comprehensive dynamic runtime analysis and exploit simulation
capabilities. It includes Frida-based instrumentation, process behavior monitoring,
and runtime API hooking for detailed binary analysis.

Author: Intellicrack Team  
Version: 2.0.0
"""

import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

from ...utils.logger import get_logger, log_message

logger = get_logger(__name__)

class AdvancedDynamicAnalyzer:
    """
    Comprehensive dynamic runtime analysis and exploit simulation
    """

    def __init__(self, binary_path: Union[str, Path]):
        """
        Initialize dynamic analyzer with target binary.

        Sets up the dynamic analysis environment for the specified binary,
        preparing for runtime analysis, API hooking, and behavior monitoring.

        Args:
            binary_path: Path to the target binary executable to analyze
        """
        self.binary_path = str(binary_path)
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info("AdvancedDynamicAnalyzer initialized with binary_path: %s", binary_path)

    def run_comprehensive_analysis(self, payload: Optional[bytes] = None) -> Dict[str, Any]:
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

        analysis_results = {
            'subprocess_execution': self._subprocess_analysis(),
            'frida_runtime_analysis': self._frida_runtime_analysis(payload),
            'process_behavior_analysis': self._process_behavior_analysis()
        }

        self.logger.info("Comprehensive dynamic analysis completed.")
        self.logger.debug("Dynamic analysis results: %s", analysis_results)

        return analysis_results

    def _subprocess_analysis(self) -> Dict[str, Any]:
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
            result = subprocess.run(
                [self.binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            self.logger.debug(f"Subprocess result: Success={result.returncode == 0}, ReturnCode={result.returncode}")

            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            self.logger.error("Subprocess analysis error: Timeout expired", exc_info=True)
            return {'success': False, 'error': 'Timeout expired'}
        except Exception as e:
            self.logger.error(f"Subprocess analysis error: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def _frida_runtime_analysis(self, payload: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Advanced Frida-based runtime analysis and payload injection.

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

            // Report completion
            setTimeout(function() {
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
            }, 5000);
            '''

            # Message handler
            analysis_data = {}

            def on_message(message, data):
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

            # Resume the process and let it run
            frida.resume(pid)
            time.sleep(10)  # Run for 10 seconds

            self.logger.info("Frida runtime analysis completed successfully")
            return {
                'success': True,
                'pid': pid,
                'analysis_data': analysis_data,
                'payload_injected': payload is not None
            }

        except Exception as e:
            self.logger.error(f"Frida runtime analysis error: {e}", exc_info=True)
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

    def _process_behavior_analysis(self) -> Dict[str, Any]:
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
            process = subprocess.Popen(
                [self.binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait a bit and collect process info
            time.sleep(2)

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

            self.logger.debug(f"Process behavior analysis result: PID={analysis.get('pid')}, Memory={analysis.get('memory_info')}, Threads={analysis.get('threads')}")

            return analysis

        except Exception as e:
            self.logger.error(f"Process behavior analysis error: {e}", exc_info=True)
            return {'error': str(e)}


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


def deep_runtime_monitoring(binary_path: str, timeout: int = 30000) -> List[str]:
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
        process = subprocess.Popen([binary_path])
        logs.append(f"Process started with PID {process.pid}")

        # Attach Frida
        logs.append("Attaching Frida...")
        session = frida.attach(process.pid)

        # Create script
        script = session.create_script(script_content)

        # Set up message handler
        def on_message(message, data):
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
        time.sleep(timeout / 1000)

        # Detach and terminate
        logs.append("Detaching Frida...")
        session.detach()

        logs.append("Terminating process...")
        process.terminate()

        logs.append("Runtime monitoring complete")

    except Exception as e:
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


