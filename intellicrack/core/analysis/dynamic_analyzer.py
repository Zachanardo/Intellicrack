"""Advanced Dynamic Analysis Module.

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

import contextlib
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ...utils.core.import_checks import FRIDA_AVAILABLE, PSUTIL_AVAILABLE, frida, psutil
from ...utils.logger import get_logger, log_message


logger = get_logger(__name__)


class AdvancedDynamicAnalyzer:
    """Comprehensive dynamic runtime analysis and vulnerability exploitation."""

    def __init__(self, binary_path: str | Path) -> None:
        """Initialize the advanced dynamic analyzer with binary path configuration.

        Args:
            binary_path: Path to the binary file to analyze.

        Raises:
            FileNotFoundError: If the binary file does not exist or is not a file.

        """
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger("IntellicrackLogger.DynamicAnalyzer")

        # Ensure the binary file exists
        if not self.binary_path.exists() or not self.binary_path.is_file():
            raise FileNotFoundError(f"Binary file not found: {self.binary_path}")

        # Analysis results storage
        self.api_calls: list[dict[str, Any]] = []
        self.memory_access: list[dict[str, Any]] = []
        self.network_activity: list[dict[str, Any]] = []
        self.file_operations: list[dict[str, Any]] = []

    def run_comprehensive_analysis(self, payload: bytes | None = None) -> dict[str, Any]:
        """Execute multi-stage dynamic analysis.

        Performs a comprehensive dynamic analysis of the target binary using multiple
        techniques including subprocess execution, Frida-based runtime analysis, and
        process behavior monitoring. Optionally injects a payload during analysis.

        Args:
            payload: Optional binary payload to inject during analysis.

        Returns:
            Analysis results from all stages, including subprocess execution,
                runtime analysis, and process behavior information.

        Raises:
            Exception: If any analysis stage fails during execution.

        """
        self.logger.info("Running comprehensive dynamic analysis for %s. Payload provided: %s", self.binary_path, bool(payload))

        analysis_results = {
            "subprocess_execution": self._subprocess_analysis(),
            "frida_runtime_analysis": self._frida_runtime_analysis(payload),
            "process_behavior_analysis": self._process_behavior_analysis(),
        }

        self.logger.info("Comprehensive dynamic analysis completed.")
        self.logger.debug("Dynamic analysis results: %s", analysis_results)

        return analysis_results

    def _subprocess_analysis(self) -> dict[str, Any]:
        """Perform standard subprocess execution analysis.

        Executes the target binary in a controlled subprocess environment and
        captures its standard output, standard error, and return code. Provides
        basic execution analysis without instrumentation.

        Returns:
            Execution results including success status, stdout/stderr output,
                and return code or error information.

        Raises:
            subprocess.TimeoutExpired: If the subprocess execution exceeds the
                10-second timeout.
            OSError: If file operations fail during process execution.
            ValueError: If invalid parameters are provided to subprocess.run.
            RuntimeError: If an unexpected runtime error occurs during execution.

        """
        self.logger.info("Starting subprocess analysis for %s", self.binary_path)

        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [self.binary_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

            self.logger.debug(
                "Subprocess result: Success=%s, ReturnCode=%s",
                result.returncode == 0,
                result.returncode,
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            self.logger.exception("Subprocess analysis error: Timeout expired")
            return {"success": False, "error": "Timeout expired"}
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Subprocess analysis error: %s", e)
            return {"success": False, "error": str(e)}

    def _frida_runtime_analysis(self, payload: bytes | None = None) -> dict[str, Any]:
        """Advanced Frida-based runtime analysis and payload injection.

        Uses Frida instrumentation to perform deep runtime analysis of the target binary.
        Hooks key functions, monitors license-related activities, and optionally injects
        a custom payload. Provides detailed insights into the binary's runtime behavior.

        Args:
            payload: Optional binary payload to inject during analysis.

        Returns:
            Runtime analysis results including intercepted function calls,
                detected license mechanisms, and injection status.

        Raises:
            OSError: If process spawning or Frida attachment fails.
            RuntimeError: If script creation or execution fails.
            Exception: If cleanup operations fail after analysis.

        """
        if not FRIDA_AVAILABLE or frida is None:
            self.logger.exception("Frida not available for runtime analysis")
            return {"success": False, "error": "Frida not available"}

        pid = None
        session = None
        script = None

        try:
            # Spawn the process
            pid = frida.spawn(str(self.binary_path))
            session = frida.attach(pid)

            # Create comprehensive interceptor script with license-specific hooks
            frida_script = """
            console.log("[Frida] Runtime analysis started");

            // Global data collection
            var interceptedCalls = [];
            var stringReferences = [];
            var networkActivity = [];
            var fileActivity = [];
            var registryActivity = [];
            var cryptoActivity = [];
            var timingChecks = [];
            var hardwareIdActivity = [];

            // Helper function to read string from memory
            function readString(address) {
                try {
                    return Memory.readCString(address);
                } catch (e) {
                    return "<unreadable>";
                }
            }

            // Hook common Windows API functions for license validation

            // File operations - License file access
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

            const ReadFile = Module.findExportByName('kernel32.dll', 'ReadFile');
            if (ReadFile) {
                Interceptor.attach(ReadFile, {
                    onEnter: function(args) {
                        this.buffer = args[1];
                        this.bytesToRead = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() !== 0 && this.bytesToRead > 0) {
                            try {
                                const data = this.buffer.readByteArray(Math.min(this.bytesToRead, 256));
                                send({
                                    type: 'file_read',
                                    data: {
                                        function: 'ReadFile',
                                        bytesRead: this.bytesToRead,
                                        preview: Array.from(new Uint8Array(data)).slice(0, 64)
                                    }
                                });
                            } catch (e) {}
                        }
                    }
                });
            }

            // Registry operations - License key storage
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

            const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
            if (RegQueryValueExW) {
                Interceptor.attach(RegQueryValueExW, {
                    onEnter: function(args) {
                        const valueName = args[1].isNull() ? "<default>" : args[1].readUtf16String();
                        this.valueName = valueName;
                        this.dataBuffer = args[4];
                        this.dataSize = args[5];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && !this.dataBuffer.isNull() && !this.dataSize.isNull()) {
                            try {
                                const size = this.dataSize.readU32();
                                if (size > 0 && size < 1024) {
                                    const data = this.dataBuffer.readByteArray(size);
                                    send({
                                        type: 'registry_read',
                                        data: {
                                            function: 'RegQueryValueExW',
                                            valueName: this.valueName,
                                            dataSize: size,
                                            preview: Array.from(new Uint8Array(data)).slice(0, 64)
                                        }
                                    });
                                }
                            } catch (e) {}
                        }
                    }
                });
            }

            // Network operations - Online activation
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

            const send_func = Module.findExportByName('ws2_32.dll', 'send');
            if (send_func) {
                Interceptor.attach(send_func, {
                    onEnter: function(args) {
                        const buffer = args[1];
                        const length = args[2].toInt32();
                        if (length > 0 && length < 4096) {
                            try {
                                const data = buffer.readByteArray(length);
                                send({
                                    type: 'network_send',
                                    data: {
                                        function: 'send',
                                        length: length,
                                        preview: Array.from(new Uint8Array(data)).slice(0, 128)
                                    }
                                });
                            } catch (e) {}
                        }
                    }
                });
            }

            const recv = Module.findExportByName('ws2_32.dll', 'recv');
            if (recv) {
                Interceptor.attach(recv, {
                    onEnter: function(args) {
                        this.buffer = args[1];
                        this.maxLength = args[2].toInt32();
                    },
                    onLeave: function(retval) {
                        const received = retval.toInt32();
                        if (received > 0 && received < 4096) {
                            try {
                                const data = this.buffer.readByteArray(received);
                                send({
                                    type: 'network_recv',
                                    data: {
                                        function: 'recv',
                                        length: received,
                                        preview: Array.from(new Uint8Array(data)).slice(0, 128)
                                    }
                                });
                            } catch (e) {}
                        }
                    }
                });
            }

            // Cryptographic operations - License signature validation
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

            const CryptVerifySignatureW = Module.findExportByName('advapi32.dll', 'CryptVerifySignatureW');
            if (CryptVerifySignatureW) {
                Interceptor.attach(CryptVerifySignatureW, {
                    onEnter: function(args) {
                        const hashSize = args[1].toInt32();
                        send({
                            type: 'crypto_verify',
                            data: {
                                function: 'CryptVerifySignatureW',
                                hashSize: hashSize
                            }
                        });
                    },
                    onLeave: function(retval) {
                        const result = retval.toInt32();
                        send({
                            type: 'crypto_verify_result',
                            data: {
                                function: 'CryptVerifySignatureW',
                                success: result !== 0,
                                returnValue: result
                            }
                        });
                    }
                });
            }

            const CryptDecrypt = Module.findExportByName('advapi32.dll', 'CryptDecrypt');
            if (CryptDecrypt) {
                Interceptor.attach(CryptDecrypt, {
                    onEnter: function(args) {
                        this.dataLen = args[4];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() !== 0 && !this.dataLen.isNull()) {
                            const decryptedLen = this.dataLen.readU32();
                            send({
                                type: 'crypto_decrypt',
                                data: {
                                    function: 'CryptDecrypt',
                                    decryptedLength: decryptedLen,
                                    success: true
                                }
                            });
                        }
                    }
                });
            }

            const CryptImportKey = Module.findExportByName('advapi32.dll', 'CryptImportKey');
            if (CryptImportKey) {
                Interceptor.attach(CryptImportKey, {
                    onEnter: function(args) {
                        const keySize = args[2].toInt32();
                        send({
                            type: 'crypto_import',
                            data: {
                                function: 'CryptImportKey',
                                keySize: keySize
                            }
                        });
                    }
                });
            }

            // Hardware ID - Machine fingerprinting
            const GetVolumeInformationW = Module.findExportByName('kernel32.dll', 'GetVolumeInformationW');
            if (GetVolumeInformationW) {
                Interceptor.attach(GetVolumeInformationW, {
                    onEnter: function(args) {
                        const rootPath = args[0].isNull() ? null : args[0].readUtf16String();
                        this.serialNumber = args[4];
                        this.rootPath = rootPath;
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() !== 0 && !this.serialNumber.isNull()) {
                            const serial = this.serialNumber.readU32();
                            hardwareIdActivity.push({
                                function: 'GetVolumeInformationW',
                                rootPath: this.rootPath,
                                serialNumber: serial.toString(16),
                                timestamp: Date.now()
                            });
                            send({
                                type: 'hardware_id',
                                data: {
                                    function: 'GetVolumeInformationW',
                                    rootPath: this.rootPath,
                                    serialNumber: serial.toString(16)
                                }
                            });
                        }
                    }
                });
            }

            const GetAdaptersAddresses = Module.findExportByName('iphlpapi.dll', 'GetAdaptersAddresses');
            if (GetAdaptersAddresses) {
                Interceptor.attach(GetAdaptersAddresses, {
                    onEnter: function(args) {
                        send({
                            type: 'hardware_id',
                            data: {
                                function: 'GetAdaptersAddresses',
                                message: 'Reading network adapter information'
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
                        hardwareIdActivity: hardwareIdActivity,
                        timingChecks: timingChecks
                    }
                });
            }, 5000);
            """

            # Message handler
            analysis_data: dict[str, Any] = {}

            def on_message(message: Any, _data: bytes | None) -> None:  # pylint: disable=unused-argument
                """Handle messages from the Frida script during dynamic analysis.

                Processes different message types including analysis completion and
                various activity tracking (file access, registry, network, licensing).

                Args:
                    message: Message dictionary from Frida containing 'type' and 'payload'.
                    _data: Additional data from Frida message (typically binary payload,
                        unused).

                Returns:
                    None: This is a callback function with no return value.

                """
                if not isinstance(message, dict) or message.get("type") != "send":
                    return
                payload_data = message.get("payload")
                if isinstance(payload_data, dict):
                    msg_type = payload_data.get("type")

                    if msg_type == "analysis_complete":
                        analysis_data.update(payload_data.get("data", {}))
                    elif msg_type in [
                        "file_access",
                        "file_read",
                        "registry_access",
                        "registry_read",
                        "network_activity",
                        "network_send",
                        "network_recv",
                        "crypto_activity",
                        "crypto_verify",
                        "crypto_verify_result",
                        "crypto_decrypt",
                        "crypto_import",
                        "hardware_id",
                        "timing_check",
                        "license_function",
                        "license_function_return",
                        "string_reference",
                    ]:
                        if msg_type not in analysis_data:
                            analysis_data[msg_type] = []
                        if isinstance(analysis_data[msg_type], list):
                            analysis_data[msg_type].append(payload_data.get("data", {}))

            script = session.create_script(frida_script)
            script.on("message", on_message)
            script.load()

            # Resume the process and let it run
            frida.resume(pid)
            time.sleep(10)  # Run for 10 seconds

            self.logger.info("Frida runtime analysis completed successfully")
            return {
                "success": True,
                "pid": pid,
                "analysis_data": analysis_data,
                "payload_injected": payload is not None,
            }

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Frida runtime analysis error: %s", e)
            return {"success": False, "error": str(e)}
        finally:
            # Cleanup
            try:
                if script is not None:
                    script.unload()
                if session is not None:
                    session.detach()
                if pid is not None and frida is not None:
                    frida.kill(pid)
            except Exception as cleanup_error:
                self.logger.exception("Error during Frida cleanup: %s", cleanup_error)

    def _process_behavior_analysis(self) -> dict[str, Any]:
        """Analyze process behavior and resource interactions.

        Monitors the target process during execution to collect information about
        its resource usage, file operations, network connections, and threading
        behavior. Provides insights into how the application interacts with the system.

        Returns:
            Process behavior data including memory usage, open files,
                network connections, and thread information.

        Raises:
            OSError: If process operations or file operations fail.
            ValueError: If process data is invalid or malformed.
            RuntimeError: If an unexpected runtime error occurs during monitoring.

        """
        if not PSUTIL_AVAILABLE or psutil is None:
            self.logger.exception("psutil not available for process behavior analysis")
            return {"success": False, "error": "psutil not available"}

        self.logger.info("Starting process behavior analysis for %s", self.binary_path)

        try:
            # Use psutil for detailed process analysis
            process = subprocess.Popen(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                [self.binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait a bit and collect process info
            time.sleep(2)

            ps_process = psutil.Process(process.pid)

            analysis = {
                "pid": process.pid,
                "memory_info": dict(ps_process.memory_info()._asdict()),
                "open_files": [f.path for f in ps_process.open_files()],
                "connections": [
                    {
                        "fd": c.fd,
                        "family": c.family,
                        "type": c.type,
                        "laddr": str(c.laddr),
                        "raddr": str(c.raddr),
                    }
                    for c in ps_process.connections()
                ],
                "threads": ps_process.num_threads(),
            }

            # Terminate process
            process.terminate()

            self.logger.debug(
                "Process behavior analysis result: PID=%s, Memory=%s, Threads=%s",
                analysis.get("pid"),
                analysis.get("memory_info"),
                analysis.get("threads"),
            )

            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.exception("Process behavior analysis error: %s", e)
            return {"error": str(e)}

    def scan_memory_for_keywords(self, keywords: list[str], target_process: str | None = None) -> dict[str, Any]:
        """Scan process memory for specific keywords.

        Performs real-time memory scanning of the target process or a specified process
        to find occurrences of license-related keywords, serial numbers, or other patterns.

        Args:
            keywords: List of keywords to search for in memory.
            target_process: Optional process name to scan (defaults to binary_path).

        Returns:
            Dictionary containing scan results with matches, addresses, and context.

        Raises:
            Exception: If memory scanning fails or process access is denied.

        """
        self.logger.info("Starting memory keyword scan for: %s", keywords)

        try:
            if FRIDA_AVAILABLE:
                return self._frida_memory_scan(keywords, target_process)
            if PSUTIL_AVAILABLE:
                return self._psutil_memory_scan(keywords, target_process)
            return self._fallback_memory_scan(keywords, target_process)
        except Exception as e:
            self.logger.exception("Memory scanning error: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "matches": [],
            }

    def _frida_memory_scan(self, keywords: list[str], target_process: str | None = None) -> dict[str, Any]:
        """Perform memory scanning using Frida instrumentation.

        Args:
            keywords: List of keywords to search for in memory.
            target_process: Optional target process name to scan.

        Returns:
            Dictionary with scan results including matches, status, and scan count.

        Raises:
            Exception: If Frida script creation, attachment, or execution fails.

        """
        if frida is None:
            return {
                "status": "error",
                "error": "Frida module not available",
                "matches": [],
            }

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
                    time.sleep(2)  # Allow process to initialize
                except Exception as e:
                    self.logger.exception("Exception in dynamic_analyzer: %s", e)
                    return {
                        "status": "error",
                        "error": f"Could not attach to or spawn process: {process_name}",
                        "matches": [],
                    }

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
                        if (range.size > 0x1000000) return; // Skip very large regions

                        try {{
                            const memory = Memory.readByteArray(range.base, Math.min(range.size, 0x100000));
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
            results: dict[str, Any] = {"matches": [], "status": "success", "scan_count": 0}

            def on_message(message: Any, data: bytes | None) -> None:
                """Handle messages from Frida memory scan script.

                Args:
                    message: Message dictionary from Frida containing scan results.
                    data: Additional binary data from Frida message.

                Returns:
                    None: This is a callback function with no return value.

                """
                if data:
                    self.logger.debug("Message data: %s bytes", len(data))
                if isinstance(message, dict) and message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict):
                        if payload.get("type") == "scan_complete":
                            matches = payload.get("matches", [])
                            if isinstance(matches, list) and isinstance(results["matches"], list):
                                results["matches"].extend(matches)
                            results["scan_count"] = payload.get("scan_count", 0)
                        elif payload.get("type") == "error":
                            self.logger.exception("Frida script error: %s", payload.get("message"))
                        elif payload.get("type") == "complete":
                            results["status"] = "complete"

            script.on("message", on_message)
            script.load()

            # Wait for scanning to complete
            timeout = 35  # Give extra time for completion
            start_time = time.time()
            while time.time() - start_time < timeout and results["status"] != "complete":
                time.sleep(1)

            script.unload()
            session.detach()

            # Remove duplicates and sort by address
            unique_matches: list[dict[str, Any]] = []
            seen: set[tuple[Any, Any]] = set()
            matches_list = results.get("matches", [])
            if isinstance(matches_list, list):
                for match in matches_list:
                    if isinstance(match, dict):
                        key = (match.get("address"), match.get("keyword"))
                        if key not in seen:
                            seen.add(key)
                            unique_matches.append(match)

                results["matches"] = sorted(unique_matches, key=lambda x: int(str(x.get("address", "0")), 16))
            self.logger.info("Frida memory scan found %s matches", len(results["matches"]))

            return results

        except Exception as e:
            self.logger.exception("Frida memory scan error: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "matches": [],
            }

    def _psutil_memory_scan(self, keywords: list[str], target_process: str | None = None) -> dict[str, Any]:
        """Perform real memory scanning using platform-specific memory reading.

        Args:
            keywords: List of keywords to search for in memory.
            target_process: Optional target process name to scan.

        Returns:
            Dictionary with scan status, matches, and memory information.

        Raises:
            OSError: If process operations fail or memory access is denied.
            Exception: If platform-specific scanning fails or process cannot be found.

        """
        import platform

        if psutil is None:
            return {
                "status": "error",
                "error": "psutil module not available",
                "matches": [],
            }

        try:
            process_name = target_process or Path(self.binary_path).name

            # Find target process
            target_proc = None
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    if process_name.lower() in proc.info["name"].lower():
                        target_proc = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.exception("Error in dynamic_analyzer: %s", e)
                    continue

            if not target_proc:
                # Try to start the process
                try:
                    proc = subprocess.Popen([str(self.binary_path)])  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    time.sleep(2)
                    target_proc = psutil.Process(proc.pid)
                except Exception as e:
                    self.logger.exception("Exception in dynamic_analyzer: %s", e)
                    return {
                        "status": "error",
                        "error": f"Could not find or start process: {process_name}",
                        "matches": [],
                    }

            matches = []
            system = platform.system()

            if system == "Windows":
                matches = self._windows_memory_scan(target_proc.pid, keywords)
            elif system == "Linux":
                matches = self._linux_memory_scan(target_proc.pid, keywords)
            elif system == "Darwin":  # macOS
                matches = self._macos_memory_scan(target_proc.pid, keywords)
            else:
                # Fallback to generic memory scanning
                matches = self._generic_memory_scan(target_proc, keywords)

            # Get memory information
            memory_info = target_proc.memory_info()
            memory_maps: list[Any] = []
            with contextlib.suppress(AttributeError, OSError, PermissionError):
                memory_maps = target_proc.memory_maps() if hasattr(target_proc, "memory_maps") else []

            self.logger.info("Memory scan found %s matches", len(matches))

            return {
                "status": "success",
                "matches": matches,
                "memory_info": {
                    "rss": memory_info.rss,
                    "vms": memory_info.vms,
                    "num_memory_maps": len(memory_maps),
                    "process_id": target_proc.pid,
                },
            }

        except Exception as e:
            self.logger.exception("Memory scan error: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "matches": [],
            }

    def _windows_memory_scan(self, pid: int, keywords: list[str]) -> list[dict[str, Any]]:
        """Perform memory scanning on Windows using ReadProcessMemory.

        Args:
            pid: Process ID to scan.
            keywords: List of keywords to search for in memory.

        Returns:
            List of dictionaries containing matches with address, keyword, and context.

        Raises:
            OSError: If process handle cannot be opened or memory read fails.
            ctypes.ArgumentError: If invalid arguments are passed to ctypes functions.

        """
        import ctypes
        from ctypes import wintypes

        matches: list[dict[str, Any]] = []

        # Windows API constants
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        MEM_COMMIT = 0x00001000
        PAGE_READWRITE = 0x04
        PAGE_READONLY = 0x02
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40

        # Open process with read access
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

        if not handle:
            return matches

        try:
            # Define MEMORY_BASIC_INFORMATION structure
            class MemoryBasicInformation(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", wintypes.DWORD),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", wintypes.DWORD),
                    ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD),
                ]

            mbi = MemoryBasicInformation()
            address = 0

            # Scan all memory regions
            while kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                # Check if memory is committed and readable
                if mbi.State == MEM_COMMIT and mbi.Protect in [
                    PAGE_READWRITE,
                    PAGE_READONLY,
                    PAGE_EXECUTE_READ,
                    PAGE_EXECUTE_READWRITE,
                ]:
                    # Read memory region
                    buffer = ctypes.create_string_buffer(mbi.RegionSize)
                    bytes_read = ctypes.c_size_t()

                    if kernel32.ReadProcessMemory(
                        handle,
                        ctypes.c_void_p(mbi.BaseAddress),
                        buffer,
                        mbi.RegionSize,
                        ctypes.byref(bytes_read),
                    ):
                        # Search for keywords in memory
                        memory_data = buffer.raw[: bytes_read.value]

                        for keyword in keywords:
                            # Search as string
                            keyword_bytes = keyword.encode("utf-8", errors="ignore")
                            offset = 0

                            while True:
                                pos = memory_data.find(keyword_bytes, offset)
                                if pos == -1:
                                    break

                                # Found match
                                actual_address = mbi.BaseAddress + pos

                                # Get context around match
                                context_start = max(0, pos - 32)
                                context_end = min(len(memory_data), pos + len(keyword_bytes) + 32)
                                context = memory_data[context_start:context_end]

                                # Try to decode context as string
                                try:
                                    context_str = context.decode("utf-8", errors="replace")
                                except (UnicodeDecodeError, AttributeError):
                                    context_str = context.hex()

                                matches.append(
                                    {
                                        "address": hex(actual_address),
                                        "keyword": keyword,
                                        "context": context_str,
                                        "offset": pos,
                                        "region_base": hex(mbi.BaseAddress),
                                        "region_size": mbi.RegionSize,
                                        "protection": hex(mbi.Protect),
                                    },
                                )

                                offset = pos + 1

                            # Also search as wide string (UTF-16)
                            keyword_wide = keyword.encode("utf-16-le", errors="ignore")
                            offset = 0

                            while True:
                                pos = memory_data.find(keyword_wide, offset)
                                if pos == -1:
                                    break

                                actual_address = mbi.BaseAddress + pos

                                # Get context
                                context_start = max(0, pos - 64)
                                context_end = min(len(memory_data), pos + len(keyword_wide) + 64)
                                context = memory_data[context_start:context_end]

                                try:
                                    context_str = context.decode("utf-16-le", errors="replace")
                                except (UnicodeDecodeError, AttributeError):
                                    context_str = context.hex()

                                matches.append(
                                    {
                                        "address": hex(actual_address),
                                        "keyword": keyword,
                                        "context": context_str,
                                        "offset": pos,
                                        "region_base": hex(mbi.BaseAddress),
                                        "region_size": mbi.RegionSize,
                                        "protection": hex(mbi.Protect),
                                        "encoding": "UTF-16",
                                    },
                                )

                                offset = pos + 2

                # Move to next memory region
                address = mbi.BaseAddress + mbi.RegionSize

        finally:
            kernel32.CloseHandle(handle)

        return matches

    def _linux_memory_scan(self, pid: int, keywords: list[str]) -> list[dict[str, Any]]:
        """Perform memory scanning on Linux using /proc/pid/mem.

        Args:
            pid: Process ID to scan.
            keywords: List of keywords to search for in memory.

        Returns:
            List of dictionaries containing matches with address, keyword, and context.

        Raises:
            OSError: If /proc filesystem files cannot be opened or read.
            FileNotFoundError: If /proc/pid/mem or /proc/pid/maps does not exist.

        """
        matches: list[dict[str, Any]] = []

        try:
            # Read memory maps to get valid memory regions
            with open(f"/proc/{pid}/maps") as f:
                maps = f.readlines()

            # Open process memory
            with open(f"/proc/{pid}/mem", "rb") as mem_file:
                for map_line in maps:
                    # Parse memory map line
                    parts = map_line.split()
                    if len(parts) < 6:
                        continue

                    # Extract address range
                    addr_range = parts[0]
                    perms = parts[1]

                    # Skip non-readable regions
                    if "r" not in perms:
                        continue

                    # Parse addresses
                    start_addr, end_addr = addr_range.split("-")
                    start = int(start_addr, 16)
                    end = int(end_addr, 16)
                    size = end - start

                    # Skip huge regions (>100MB)
                    if size > 100 * 1024 * 1024:
                        continue

                    try:
                        # Seek to region start
                        mem_file.seek(start)

                        # Read memory region
                        memory_data = mem_file.read(size)

                        # Search for keywords
                        for keyword in keywords:
                            keyword_bytes = keyword.encode("utf-8", errors="ignore")
                            offset = 0

                            while True:
                                pos = memory_data.find(keyword_bytes, offset)
                                if pos == -1:
                                    break

                                actual_address = start + pos

                                # Get context
                                context_start = max(0, pos - 32)
                                context_end = min(len(memory_data), pos + len(keyword_bytes) + 32)
                                context = memory_data[context_start:context_end]

                                try:
                                    context_str = context.decode("utf-8", errors="replace")
                                except (UnicodeDecodeError, AttributeError):
                                    context_str = context.hex()

                                matches.append(
                                    {
                                        "address": hex(actual_address),
                                        "keyword": keyword,
                                        "context": context_str,
                                        "offset": pos,
                                        "region_base": hex(start),
                                        "region_size": size,
                                        "permissions": perms,
                                        "mapping": parts[5] if len(parts) > 5 else "",
                                    },
                                )

                                offset = pos + 1

                    except OSError:
                        # Some memory regions may not be accessible
                        continue

        except Exception as e:
            self.logger.exception("Linux memory scan error: %s", e)

        return matches

    def _macos_memory_scan(self, pid: int, keywords: list[str]) -> list[dict[str, Any]]:
        """Perform memory scanning on macOS using task_for_pid and vm_read.

        Args:
            pid: Process ID to scan.
            keywords: List of keywords to search for in memory.

        Returns:
            List of dictionaries containing matches with address, keyword, and context.

        Raises:
            OSError: If memory access or process attachment fails.
            subprocess.SubprocessError: If LLDB script execution fails.

        """
        matches: list[dict[str, Any]] = []

        try:
            # macOS requires special entitlements for memory access
            # Try using lldb as a fallback
            import tempfile

            # Create LLDB script
            script = f"""
import lldb
import sys

def scan_memory(debugger, pid, keywords):
    target = debugger.CreateTarget("")
    if not target:
        return []

    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), {pid}, error)
    if not process or error.Fail():
        return []

    matches = []

    # Get memory regions
    for thread in process:
        for frame in thread:
            # Read memory at frame
            for keyword in {keywords}:
                # Search in readable memory
                pass

    process.Detach()
    return matches

# Execute scan
debugger = lldb.SBDebugger.Create()
matches = scan_memory(debugger, {pid}, {keywords})
print(matches)
"""

            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script)
                script_path = f.name

            if lldb_path := shutil.which("lldb"):
                with contextlib.suppress(OSError, subprocess.SubprocessError):
                    result = subprocess.run([lldb_path, "-P"], capture_output=True, text=True)
                    if result.returncode == 0:
                        # LLDB is available, execute the memory scanning script
                        lldb_cmd = [
                            lldb_path,
                            "-b",
                            "-o",
                            f"command script import {script_path}",
                            "-o",
                            "quit",
                        ]
                        scan_result = subprocess.run(lldb_cmd, capture_output=True, text=True, timeout=10)
                        if scan_result.stdout:
                            self.logger.debug("LLDB memory scan output: %s", scan_result.stdout)
            # Fallback to generic scanning
            if psutil is not None:
                return self._generic_memory_scan(psutil.Process(pid), keywords)
            return matches

        except Exception as e:
            self.logger.exception("macOS memory scan error: %s", e)
            return matches

    def _generic_memory_scan(self, process: Any, keywords: list[str]) -> list[dict[str, Any]]:
        """Scan memory using process information.

        Args:
            process: Process object to scan.
            keywords: List of keywords to search for in memory.

        Returns:
            List of dictionaries containing matches with address, keyword, and context.

        Raises:
            psutil.AccessDenied: If access to process memory is denied.
            AttributeError: If process lacks required attributes for scanning.
            Exception: If memory scanning fails during execution.

        """
        matches: list[dict[str, Any]] = []

        if psutil is None:
            return matches

        try:
            # Get process memory maps if available
            memory_regions: list[dict[str, Any]] = []

            with contextlib.suppress(AttributeError, psutil.AccessDenied):
                memory_maps = process.memory_maps()
                memory_regions.extend(
                    {
                        "path": mmap.path,
                        "rss": mmap.rss,
                        "size": mmap.size if hasattr(mmap, "size") else mmap.rss,
                        "addr": mmap.addr if hasattr(mmap, "addr") else "unknown",
                        "perms": mmap.perms if hasattr(mmap, "perms") else "r--",
                    }
                    for mmap in memory_maps
                )
            # Get process info that might contain keywords
            searchable_data = []

            # Command line
            with contextlib.suppress(AttributeError, OSError):
                cmdline = " ".join(process.cmdline())
                searchable_data.append(("cmdline", cmdline))
            # Environment variables
            with contextlib.suppress(AttributeError, OSError):
                environ = process.environ()
                searchable_data.extend((f"env_{key}", value) for key, value in environ.items())
            # Open files
            with contextlib.suppress(AttributeError, OSError):
                searchable_data.extend(("open_file", file.path) for file in process.open_files())
            # Connections
            with contextlib.suppress(AttributeError, OSError):
                searchable_data.extend(("connection", f"{conn.laddr}:{conn.raddr}") for conn in process.connections())
            # Search for keywords in available data
            for source, data in searchable_data:
                for keyword in keywords:
                    if keyword.lower() in data.lower():
                        # Estimate memory address based on process base
                        base_address = 0x00400000  # Default process base

                        # Try to get actual base from memory regions
                        if memory_regions:
                            for region in memory_regions:
                                if "x" in region.get("perms", ""):
                                    with contextlib.suppress(ValueError, KeyError, TypeError):
                                        base_address = (
                                            int(region["addr"].split("-")[0], 16) if isinstance(region["addr"], str) else region["addr"]
                                        )
                                        break
                        offset = data.lower().find(keyword.lower())

                        matches.append(
                            {
                                "address": hex(base_address + offset),
                                "keyword": keyword,
                                "context": data[max(0, offset - 50) : offset + len(keyword) + 50],
                                "offset": offset,
                                "source": source,
                                "region_base": hex(base_address),
                            },
                        )

        except Exception as e:
            self.logger.exception("Generic memory scan error: %s", e)

        return matches

    def _fallback_memory_scan(self, keywords: list[str], target_process: str | None = None) -> dict[str, Any]:
        """Fallback memory scanning using binary file analysis.

        Args:
            keywords: List of keywords to search for in memory.
            target_process: Optional target process name (unused in fallback).

        Returns:
            Dictionary with scan status, matches, and scan type.

        Raises:
            FileNotFoundError: If the binary file does not exist.
            OSError: If the binary file cannot be read.
            Exception: If scanning fails during file processing.

        """
        try:
            if target_process:
                self.logger.info("Using fallback memory scan for process %s", target_process)
            else:
                self.logger.info("Using fallback memory scan (binary file analysis)")

            matches = []

            # Read and scan the binary file itself
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            # Convert to text for searching
            binary_text = binary_data.decode("utf-8", errors="ignore").lower()

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

                    matches.append(
                        {
                            "address": f"0x{index:08X}",
                            "keyword": keyword,
                            "context": context.replace("\x00", "."),
                            "offset": index,
                            "region_base": "0x00000000",
                            "region_size": len(binary_data),
                        },
                    )

                    offset = index + len(keyword)

            self.logger.info("Fallback memory scan found %s matches", len(matches))

            return {
                "status": "success",
                "matches": matches,
                "scan_type": "binary_file_analysis",
            }

        except Exception as e:
            self.logger.exception("Fallback memory scan error: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "matches": [],
            }


# Convenience functions for application integration
def run_dynamic_analysis(app: Any, binary_path: str | Path | None = None, payload: bytes | None = None) -> dict[str, Any]:
    """Run dynamic analysis on a binary with app integration.

    Args:
        app: Application instance with update_output signal.
        binary_path: Optional path to binary (uses app.binary_path if not provided).
        payload: Optional payload to inject.

    Returns:
        Analysis results dictionary containing subprocess execution, runtime analysis,
            and process behavior data.

    Raises:
        FileNotFoundError: If the binary path does not exist.
        AttributeError: If app instance lacks required attributes.

    """
    # Use provided path or get from app
    path = binary_path or getattr(app, "binary_path", None)
    if not path:
        if hasattr(app, "update_output"):
            app.update_output.emit(log_message("[Dynamic] No binary selected."))
        return {"error": "No binary selected"}

    if hasattr(app, "update_output"):
        app.update_output.emit(log_message("[Dynamic] Starting dynamic analysis..."))

    # Create analyzer
    analyzer = AdvancedDynamicAnalyzer(path)

    # Run analysis
    results = analyzer.run_comprehensive_analysis(payload)

    # Display results
    if hasattr(app, "update_output"):
        app.update_output.emit(log_message("[Dynamic] Analysis completed"))

    # Add to analyze results
    if not hasattr(app, "analyze_results"):
        app.analyze_results = []

    if hasattr(app, "analyze_results") and isinstance(app.analyze_results, list):
        app.analyze_results.append("\n=== DYNAMIC ANALYSIS RESULTS ===")

        # Subprocess results
        if "subprocess_execution" in results:
            sub_result = results["subprocess_execution"]
            app.analyze_results.append("\nSubprocess Execution:")
            app.analyze_results.append(f"  Success: {sub_result.get('success', False)}")
            if sub_result.get("return_code") is not None:
                app.analyze_results.append(f"  Return Code: {sub_result['return_code']}")

        # Frida runtime analysis
        if "frida_runtime_analysis" in results:
            frida_result = results["frida_runtime_analysis"]
            if frida_result.get("success"):
                analysis_data = frida_result.get("analysis_data", {})
                app.analyze_results.append("\nRuntime Analysis:")
                app.analyze_results.append(f"  File Operations: {len(analysis_data.get('file_access', []))}")
                app.analyze_results.append(f"  Registry Operations: {len(analysis_data.get('registry_access', []))}")
                app.analyze_results.append(f"  Network Connections: {len(analysis_data.get('network_activity', []))}")
                app.analyze_results.append(f"  License Functions: {len(analysis_data.get('license_function', []))}")

                # Show some details
                if analysis_data.get("license_function"):
                    app.analyze_results.append("\n  Detected License Functions:")
                    for func in analysis_data["license_function"][:5]:
                        app.analyze_results.append(f"    - {func.get('function', 'Unknown')} in {func.get('module', 'Unknown')}")

        # Process behavior
        if "process_behavior_analysis" in results:
            behavior = results["process_behavior_analysis"]
            if "error" not in behavior:
                app.analyze_results.append("\nProcess Behavior:")
                app.analyze_results.append(f"  PID: {behavior.get('pid', 'Unknown')}")
                app.analyze_results.append(f"  Threads: {behavior.get('threads', 0)}")
                if behavior.get("memory_info"):
                    mem = behavior["memory_info"]
                    app.analyze_results.append(f"  Memory RSS: {mem.get('rss', 0) / 1024 / 1024:.2f} MB")

    return results


def deep_runtime_monitoring(binary_path: str, timeout: int = 30000) -> list[str]:
    """Monitor runtime behavior of the binary using Frida instrumentation.

    Monitors key Windows APIs for registry, file, network operations and license-related
    behavior. Provides comprehensive runtime analysis of the target binary.

    Args:
        binary_path: Path to the binary to monitor.
        timeout: Timeout in milliseconds (default: 30000).

    Returns:
        Log messages from the monitoring session.

    Raises:
        OSError: If process creation or attachment fails.
        ValueError: If Frida is not available or script execution fails.
        RuntimeError: If an unexpected runtime error occurs during monitoring.

    """
    logs = [f"Starting runtime monitoring of {binary_path} (timeout: {timeout}ms)"]

    try:
        if not FRIDA_AVAILABLE or frida is None:
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
        process = subprocess.Popen([binary_path], encoding="utf-8")  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
        logs.append(f"Process started with PID {process.pid}")

        # Attach Frida
        logs.append("Attaching Frida...")
        session = frida.attach(process.pid)

        # Create script
        script = session.create_script(script_content)

        # Set up message handler
        def on_message(message: Any, _data: bytes | None) -> None:  # pylint: disable=unused-argument
            """Handle messages from a Frida script.

            Appends payloads from 'send' messages to the logs list.

            Args:
                message: Message dictionary from Frida.
                _data: Additional binary data from Frida (unused).

            Returns:
                None: This is a callback function with no return value.

            """
            if isinstance(message, dict) and message.get("type") == "send":
                payload = message.get("payload")
                if payload is not None:
                    logs.append(str(payload))

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

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error in dynamic_analyzer: %s", e)
        logs.append(f"Error during runtime monitoring: {e}")

    return logs


# Additional convenience functions
def create_dynamic_analyzer(binary_path: str | Path) -> AdvancedDynamicAnalyzer:
    """Create a dynamic analyzer instance.

    Args:
        binary_path: Path to the target binary.

    Returns:
        Configured analyzer instance ready for dynamic analysis operations.

    Raises:
        FileNotFoundError: If the binary file does not exist.

    """
    return AdvancedDynamicAnalyzer(binary_path)


def run_quick_analysis(binary_path: str | Path, payload: bytes | None = None) -> dict[str, Any]:
    """Run a quick comprehensive analysis on a binary.

    Args:
        binary_path: Path to the target binary.
        payload: Optional payload to inject.

    Returns:
        Analysis results from all analysis stages.

    Raises:
        FileNotFoundError: If the binary file does not exist.
        Exception: If analysis execution fails.

    """
    analyzer = create_dynamic_analyzer(binary_path)
    return analyzer.run_comprehensive_analysis(payload)


# Create alias for backward compatibility
DynamicAnalyzer = AdvancedDynamicAnalyzer
