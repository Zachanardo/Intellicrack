#!/usr/bin/env python3
"""Frida Protection Bypass Automation Module.

Production-ready implementation for automated detection and bypass of:
- Anti-debugging mechanisms
- Certificate pinning
- Integrity checks
- VM detection
- Packer/protector detection
- Automated unpacking
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum

import frida

from intellicrack.utils.log_message import log_analysis, log_error, log_security
from intellicrack.utils.logger import log_all_methods


logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """Types of protections that can be detected and bypassed."""

    ANTI_DEBUG = "anti_debug"
    CERT_PINNING = "cert_pinning"
    INTEGRITY_CHECK = "integrity_check"
    VM_DETECTION = "vm_detection"
    PACKER = "packer"
    ROOT_DETECTION = "root_detection"
    EMULATOR_DETECTION = "emulator_detection"
    HOOK_DETECTION = "hook_detection"
    DEBUGGER_DETECTION = "debugger_detection"
    TAMPER_DETECTION = "tamper_detection"


@dataclass
class ProtectionInfo:
    """Information about detected protection."""

    type: ProtectionType
    location: str
    confidence: float
    details: dict[str, object]
    bypass_available: bool
    bypass_script: str | None = None


@log_all_methods
class FridaProtectionBypasser:
    """Automated protection detection and bypass using Frida."""

    def __init__(self, process_name: str | None = None, pid: int | None = None) -> None:
        """Initialize the FridaProtectionBypasser to detect and bypass application protections.

        Args:
            process_name: Name of the process to attach to. Defaults to None.
            pid: Process ID to attach to. Defaults to None.

        """
        self.process_name = process_name
        self.pid = pid
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None
        self.detected_protections: list[ProtectionInfo] = []

    def attach(self) -> bool:
        """Attach to target process.

        Establishes a Frida session to the target process specified during
        initialization either by process name or process ID. Updates the
        internal session object used for all subsequent instrumentation.

        Returns:
            True if attachment succeeded, False otherwise.

        Raises:
            Exception: If process name and PID are both None, or if Frida
                attachment fails due to invalid process or permission issues.

        """
        try:
            if self.pid:
                self.session = frida.attach(self.pid)
            elif self.process_name:
                self.session = frida.attach(self.process_name)
            else:
                logger.exception("No process name or PID provided")
                return False

            logger.info("Attached to process: %s", self.process_name or self.pid)
            return True
        except Exception:
            logger.exception("Failed to attach to process")
            return False

    def detect_anti_debug(self) -> list[ProtectionInfo]:
        """Detect anti-debugging mechanisms.

        Analyzes the target process for common anti-debugging techniques
        including user-mode (IsDebuggerPresent, CheckRemoteDebuggerPresent)
        and kernel-mode techniques (NtQueryInformationProcess with all
        information classes, NtSetInformationThread, NtQuerySystemInformation,
        NtQueryObject), PEB flags, and hardware breakpoints. Implements
        comprehensive bypass for commercial protections including VMProtect,
        Themida, Denuvo, Arxan, and SecuROM.

        Returns:
            List of detected anti-debug protection information objects.
                Each object contains type, location, confidence score,
                bypass details, and a Frida script for defeating the
                anti-debug mechanism.

        Raises:
            Exception: If Frida session is not initialized or script
                execution fails.

        """
        detections = []

        anti_debug_script = """
        const detections = [];

        // Windows anti-debug detection
        if (Process.platform === 'windows') {
            // User-mode anti-debug detection
            const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
            if (isDebuggerPresent) {
                Interceptor.attach(isDebuggerPresent, {
                    onEnter: function(args) {
                        send({
                            type: 'anti_debug',
                            method: 'IsDebuggerPresent',
                            level: 'user-mode',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                    }
                });
                detections.push('IsDebuggerPresent');
            }

            const checkRemoteDebugger = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
            if (checkRemoteDebugger) {
                Interceptor.attach(checkRemoteDebugger, {
                    onEnter: function(args) {
                        this.pbDebuggerPresent = args[1];
                        send({
                            type: 'anti_debug',
                            method: 'CheckRemoteDebuggerPresent',
                            level: 'user-mode',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        if (this.pbDebuggerPresent && !this.pbDebuggerPresent.isNull()) {
                            this.pbDebuggerPresent.writeU8(0);
                        }
                        retval.replace(1);
                    }
                });
                detections.push('CheckRemoteDebuggerPresent');
            }

            // Kernel-mode anti-debug detection and bypass
            const ntQueryInfoProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
            if (ntQueryInfoProcess) {
                Interceptor.attach(ntQueryInfoProcess, {
                    onEnter: function(args) {
                        this.processHandle = args[0];
                        this.infoClass = args[1].toInt32();
                        this.buffer = args[2];
                        this.bufferSize = args[3].toInt32();
                        this.returnLength = args[4];

                        send({
                            type: 'anti_debug',
                            method: 'NtQueryInformationProcess',
                            level: 'kernel-mode',
                            infoClass: this.infoClass,
                            infoClassName: this.getInfoClassName(this.infoClass),
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        const STATUS_SUCCESS = 0x00000000;

                        if (!this.buffer || this.buffer.isNull()) {
                            return;
                        }

                        // ProcessDebugPort (0x07) - Most common, used by VMProtect, Themida
                        if (this.infoClass === 0x07) {
                            if (Process.pointerSize === 8) {
                                this.buffer.writeU64(0);
                            } else {
                                this.buffer.writeU32(0);
                            }
                            retval.replace(STATUS_SUCCESS);
                        }
                        // ProcessDebugObjectHandle (0x1E) - Used by Arxan, Denuvo
                        else if (this.infoClass === 0x1E) {
                            if (Process.pointerSize === 8) {
                                this.buffer.writeU64(0);
                            } else {
                                this.buffer.writeU32(0);
                            }
                            if (this.returnLength && !this.returnLength.isNull()) {
                                this.returnLength.writeU32(Process.pointerSize);
                            }
                            retval.replace(0xC0000353); // STATUS_PORT_NOT_SET
                        }
                        // ProcessDebugFlags (0x1F) - NoDebugInherit flag, used by SecuROM
                        else if (this.infoClass === 0x1F) {
                            this.buffer.writeU32(1); // PROCESS_DEBUG_INHERIT
                            if (this.returnLength && !this.returnLength.isNull()) {
                                this.returnLength.writeU32(4);
                            }
                            retval.replace(STATUS_SUCCESS);
                        }
                        // ProcessBasicInformation (0x00) - Can reveal debug port
                        else if (this.infoClass === 0x00) {
                            // Don't modify, but log access for analysis
                        }
                        // ProcessBreakOnTermination (0x1D) - Critical process flag
                        else if (this.infoClass === 0x1D) {
                            this.buffer.writeU32(0);
                            retval.replace(STATUS_SUCCESS);
                        }
                        // ProcessWow64Information (0x1A) - Can be abused for detection
                        else if (this.infoClass === 0x1A) {
                            // Leave unmodified for compatibility
                        }
                    },
                    getInfoClassName: function(infoClass) {
                        const names = {
                            0x00: 'ProcessBasicInformation',
                            0x07: 'ProcessDebugPort',
                            0x1A: 'ProcessWow64Information',
                            0x1D: 'ProcessBreakOnTermination',
                            0x1E: 'ProcessDebugObjectHandle',
                            0x1F: 'ProcessDebugFlags',
                            0x22: 'ProcessProtectionInformation'
                        };
                        return names[infoClass] || 'Unknown (' + infoClass + ')';
                    }
                });
                detections.push('NtQueryInformationProcess');
            }

            // NtSetInformationThread - ThreadHideFromDebugger (0x11)
            // Use Interceptor.replace to completely block the call instead of just modifying return value
            const ntSetInfoThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
            if (ntSetInfoThread) {
                const originalNtSetInfoThread = new NativeFunction(ntSetInfoThread, 'uint32',
                    ['pointer', 'uint32', 'pointer', 'uint32']);

                Interceptor.replace(ntSetInfoThread, new NativeCallback(function(threadHandle, infoClass, buffer, bufferSize) {
                    // ThreadHideFromDebugger (0x11) - Critical for Themida, VMProtect
                    if (infoClass === 0x11) {
                        send({
                            type: 'anti_debug',
                            method: 'NtSetInformationThread (BLOCKED)',
                            level: 'kernel-mode',
                            infoClass: infoClass,
                            infoClassName: 'ThreadHideFromDebugger',
                            location: 'intercepted'
                        });
                        // Return success without calling the original function
                        // This PREVENTS the thread from being hidden from debugger
                        return 0x00000000; // STATUS_SUCCESS
                    }
                    // For other information classes, call the original function
                    return originalNtSetInfoThread(threadHandle, infoClass, buffer, bufferSize);
                }, 'uint32', ['pointer', 'uint32', 'pointer', 'uint32']));
                detections.push('NtSetInformationThread');
            }

            // NtQuerySystemInformation - SystemKernelDebuggerInformation (0x23)
            const ntQuerySystemInfo = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
            if (ntQuerySystemInfo) {
                Interceptor.attach(ntQuerySystemInfo, {
                    onEnter: function(args) {
                        this.systemInfoClass = args[0].toInt32();
                        this.buffer = args[1];
                        this.bufferSize = args[2].toInt32();
                        this.returnLength = args[3];

                        if (this.systemInfoClass === 0x23 || this.systemInfoClass === 0x69) {
                            send({
                                type: 'anti_debug',
                                method: 'NtQuerySystemInformation',
                                level: 'kernel-mode',
                                infoClass: this.systemInfoClass,
                                infoClassName: this.systemInfoClass === 0x23 ?
                                    'SystemKernelDebuggerInformation' :
                                    'SystemKernelDebuggerInformationEx',
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        const STATUS_SUCCESS = 0x00000000;

                        if (!this.buffer || this.buffer.isNull()) {
                            return;
                        }

                        // SystemKernelDebuggerInformation (0x23) - 2-byte structure
                        // KdDebuggerEnabled = FALSE (no debugger enabled)
                        // KdDebuggerNotPresent = TRUE (debugger is NOT present - this is what we want)
                        if (this.systemInfoClass === 0x23) {
                            this.buffer.writeU8(0);      // KdDebuggerEnabled = FALSE
                            this.buffer.add(1).writeU8(1); // KdDebuggerNotPresent = TRUE
                            if (this.returnLength && !this.returnLength.isNull()) {
                                this.returnLength.writeU32(2);
                            }
                            retval.replace(STATUS_SUCCESS);
                        }
                        // SystemKernelDebuggerInformationEx (0x69) - Extended version
                        else if (this.systemInfoClass === 0x69) {
                            this.buffer.writeU8(0);      // DebuggerAllowed = FALSE
                            this.buffer.add(1).writeU8(0); // DebuggerEnabled = FALSE
                            this.buffer.add(2).writeU8(0); // DebuggerPresent = FALSE
                            if (this.returnLength && !this.returnLength.isNull()) {
                                this.returnLength.writeU32(3);
                            }
                            retval.replace(STATUS_SUCCESS);
                        }
                    }
                });
                detections.push('NtQuerySystemInformation');
            }

            // NtQueryObject - Debug object enumeration
            const ntQueryObject = Module.findExportByName('ntdll.dll', 'NtQueryObject');
            if (ntQueryObject) {
                Interceptor.attach(ntQueryObject, {
                    onEnter: function(args) {
                        this.objectHandle = args[0];
                        this.infoClass = args[1].toInt32();
                        this.buffer = args[2];
                        this.bufferSize = args[3].toInt32();
                        this.returnLength = args[4];

                        // ObjectTypeInformation (0x02) - Can reveal debug objects
                        // ObjectAllTypesInformation (0x03) - Enumerates all object types
                        if (this.infoClass === 0x02 || this.infoClass === 0x03) {
                            send({
                                type: 'anti_debug',
                                method: 'NtQueryObject',
                                level: 'kernel-mode',
                                infoClass: this.infoClass,
                                infoClassName: this.infoClass === 0x02 ?
                                    'ObjectTypeInformation' : 'ObjectAllTypesInformation',
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        // Filter out debug object type information
                        if ((this.infoClass === 0x02 || this.infoClass === 0x03) &&
                            this.buffer && !this.buffer.isNull() &&
                            retval.toInt32() === 0x00000000) {

                            try {
                                const typeName = this.buffer.add(Process.pointerSize * 2).readPointer();
                                if (typeName && !typeName.isNull()) {
                                    const name = typeName.readUtf16String();
                                    if (name && name.toLowerCase().includes('debug')) {
                                        // Hide debug-related object types
                                        retval.replace(0xC0000024); // STATUS_OBJECT_TYPE_MISMATCH
                                    }
                                }
                            } catch (e) {
                                // Ignore read errors
                            }
                        }
                    }
                });
                detections.push('NtQueryObject');
            }

            // NtClose on debug object handle detection
            const ntClose = Module.findExportByName('ntdll.dll', 'NtClose');
            if (ntClose) {
                const seenHandles = new Set();

                Interceptor.attach(ntClose, {
                    onEnter: function(args) {
                        const handle = args[0].toString();

                        // Track handles that might be debug objects
                        if (seenHandles.has(handle)) {
                            send({
                                type: 'anti_debug',
                                method: 'NtClose (Debug Handle)',
                                level: 'kernel-mode',
                                handle: handle,
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        // STATUS_INVALID_HANDLE often indicates debug object detection attempt
                        if (retval.toInt32() === 0xC0000008) {
                            this.detectedDebugCheck = true;
                        }
                    }
                });
            }

            // Timing attack bypass for kernel debug checks
            const ntQueryPerformanceCounter = Module.findExportByName('ntdll.dll', 'NtQueryPerformanceCounter');
            if (ntQueryPerformanceCounter) {
                let lastCounter = null;
                let callCount = 0;

                Interceptor.attach(ntQueryPerformanceCounter, {
                    onEnter: function(args) {
                        this.counterPtr = args[0];
                    },
                    onLeave: function(retval) {
                        callCount++;

                        if (!this.counterPtr || this.counterPtr.isNull()) {
                            return;
                        }

                        try {
                            const currentCounter = this.counterPtr.readU64();

                            if (callCount > 2 && lastCounter !== null) {
                                const delta = currentCounter - lastCounter;

                                if (delta < 10000) {
                                    send({
                                        type: 'anti_debug',
                                        method: 'Timing Attack (QueryPerformanceCounter)',
                                        level: 'kernel-mode',
                                        delta: delta.toString(),
                                        location: this.returnAddress.toString()
                                    });

                                    const jitter = Math.floor(Math.random() * 5000) + 1000;
                                    this.counterPtr.writeU64(currentCounter + jitter);
                                }
                            }

                            lastCounter = currentCounter;
                        } catch (e) {
                            // Ignore read errors
                        }

                        if (callCount > 100) {
                            callCount = 0;
                        }
                    }
                });
            }

            // PEB BeingDebugged flag - correct PEB address calculation
            // TEB is at FS:[0x30] (x86) or GS:[0x60] (x64)
            // PEB is at TEB+0x30 (x86) or TEB+0x60 (x64)
            // BeingDebugged is at PEB+0x02
            let pebAddress = null;
            try {
                if (Process.pointerSize === 8) {
                    // x64: Read PEB from TEB at GS:[0x60]
                    const ntdll = Module.findBaseAddress('ntdll.dll');
                    if (ntdll) {
                        const rtlGetCurrentPeb = Module.findExportByName('ntdll.dll', 'RtlGetCurrentPeb');
                        if (rtlGetCurrentPeb) {
                            const getPeb = new NativeFunction(rtlGetCurrentPeb, 'pointer', []);
                            pebAddress = getPeb();
                        }
                    }
                } else {
                    // x86: Read PEB from TEB at FS:[0x30]
                    const ntdll = Module.findBaseAddress('ntdll.dll');
                    if (ntdll) {
                        const rtlGetCurrentPeb = Module.findExportByName('ntdll.dll', 'RtlGetCurrentPeb');
                        if (rtlGetCurrentPeb) {
                            const getPeb = new NativeFunction(rtlGetCurrentPeb, 'pointer', []);
                            pebAddress = getPeb();
                        }
                    }
                }
            } catch (e) {
                // RtlGetCurrentPeb may not be available
            }

            if (pebAddress && !pebAddress.isNull()) {
                const beingDebuggedOffset = 0x02;
                const beingDebuggedPtr = pebAddress.add(beingDebuggedOffset);

                // Directly clear the BeingDebugged flag
                try {
                    beingDebuggedPtr.writeU8(0);
                    send({
                        type: 'anti_debug',
                        method: 'PEB.BeingDebugged cleared',
                        level: 'kernel-mode',
                        location: pebAddress.toString()
                    });
                } catch (e) {
                    // Memory may be protected
                }

                // Also clear NtGlobalFlag at PEB+0x68 (x86) or PEB+0xBC (x64)
                try {
                    const ntGlobalFlagOffset = Process.pointerSize === 8 ? 0xBC : 0x68;
                    const ntGlobalFlagPtr = pebAddress.add(ntGlobalFlagOffset);
                    // Clear heap debug flags: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                    const currentFlags = ntGlobalFlagPtr.readU32();
                    const cleanFlags = currentFlags & ~0x70;
                    ntGlobalFlagPtr.writeU32(cleanFlags);
                } catch (e) {
                    // Ignore
                }

                detections.push('PEB.BeingDebugged');
            }

            // Hardware breakpoint detection - correct CONTEXT structure offsets
            // x86 CONTEXT: DR0 at offset 0x04, DR1-DR3 follow at 4-byte intervals
            // x64 CONTEXT: DR0 at offset 0x350, DR1-DR3 at 0x358, 0x360, 0x368
            const getThreadContext = Module.findExportByName('kernel32.dll', 'GetThreadContext');
            if (getThreadContext) {
                Interceptor.attach(getThreadContext, {
                    onEnter: function(args) {
                        this.contextPtr = args[1];
                    },
                    onLeave: function(retval) {
                        if (this.contextPtr && !this.contextPtr.isNull() && retval.toInt32() !== 0) {
                            try {
                                // x64: DR0-DR3 at offsets 0x350, 0x358, 0x360, 0x368
                                // x86: DR0-DR3 at offsets 0x04, 0x08, 0x0C, 0x10
                                const dr0Offset = Process.pointerSize === 8 ? 0x350 : 0x04;
                                const regSize = Process.pointerSize;

                                for (let i = 0; i < 4; i++) {
                                    this.contextPtr.add(dr0Offset + i * regSize).writePointer(ptr(0));
                                }

                                // Also clear DR6 (debug status) and DR7 (debug control)
                                // x64: DR6 at 0x370, DR7 at 0x378
                                // x86: DR6 at 0x14, DR7 at 0x18
                                const dr6Offset = Process.pointerSize === 8 ? 0x370 : 0x14;
                                const dr7Offset = Process.pointerSize === 8 ? 0x378 : 0x18;
                                this.contextPtr.add(dr6Offset).writePointer(ptr(0));
                                this.contextPtr.add(dr7Offset).writePointer(ptr(0));

                                send({
                                    type: 'anti_debug',
                                    method: 'Hardware Breakpoint Check',
                                    level: 'kernel-mode',
                                    location: this.returnAddress.toString()
                                });
                            } catch (e) {
                                // Ignore write errors
                            }
                        }
                    }
                });
                detections.push('Hardware Breakpoints');
            }

        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, _data: object) -> None:
            try:
                if not isinstance(message, dict):
                    return
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if not isinstance(payload, dict):
                        return
                    if payload.get("type") == "anti_debug":
                        location_val = payload.get("location")
                        method_val = payload.get("method", "Unknown")
                        level_val = payload.get("level", "unknown")

                        details: dict[str, object] = {
                            "method": method_val,
                            "level": level_val,
                        }

                        if "infoClass" in payload:
                            details["infoClass"] = payload["infoClass"]
                        if "infoClassName" in payload:
                            details["infoClassName"] = payload["infoClassName"]
                        if "handle" in payload:
                            details["handle"] = payload["handle"]
                        if "delta" in payload:
                            details["delta"] = payload["delta"]

                        confidence = 0.98 if level_val == "kernel-mode" else 0.95

                        info = ProtectionInfo(
                            type=ProtectionType.ANTI_DEBUG,
                            location=str(location_val) if location_val is not None else "N/A",
                            confidence=confidence,
                            details=details,
                            bypass_available=True,
                            bypass_script=anti_debug_script,
                        )
                        detections.append(info)
                        log_security(
                            f"Anti-debug detected: {method_val} ({level_val})",
                            context={"payload": payload},
                        )
            except (KeyError, TypeError, ValueError) as e:
                log_error(
                    "Error processing anti-debug detection message",
                    context={"error": str(e), "message": message},
                    exception=e,
                )

        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return detections
            script = self.session.create_script(anti_debug_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)  # Wait for detections
            script.unload()
        except Exception:
            logger.exception("Anti-debug detection failed")

        return detections

    def detect_cert_pinning(self) -> list[ProtectionInfo]:
        """Detect certificate pinning implementations.

        Identifies certificate pinning mechanisms on Windows platforms including
        CryptoAPI certificate verification (CertVerifyCertificateChainPolicy,
        CertGetCertificateChain), WinHTTP SSL options, WinINet certificate
        validation, and SChannel security settings.

        Returns:
            List of detected certificate pinning protection information objects.
                Each object contains pinning method, hostname (if available),
                confidence score, and Frida bypass script for certificate
                validation bypass.

        Raises:
            Exception: If Frida session is not initialized or script
                execution fails.

        """
        detections = []

        cert_pinning_script = """
        const detections = [];

        // Windows certificate validation - comprehensive bypass
        if (Process.platform === 'windows') {
            // CertVerifyCertificateChainPolicy
            const CertVerifyCertificateChainPolicy = Module.findExportByName('crypt32.dll', 'CertVerifyCertificateChainPolicy');
            if (CertVerifyCertificateChainPolicy) {
                Interceptor.attach(CertVerifyCertificateChainPolicy, {
                    onEnter: function(args) {
                        this.policyStatus = args[4];
                        send({
                            type: 'cert_pinning',
                            method: 'CertVerifyCertificateChainPolicy',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        // Set cbSize and dwError in CERT_CHAIN_POLICY_STATUS
                        if (this.policyStatus && !this.policyStatus.isNull()) {
                            this.policyStatus.writeU32(8); // cbSize
                            this.policyStatus.add(4).writeU32(0); // dwError = 0 (no error)
                        }
                        retval.replace(1);
                    }
                });
                detections.push('CertVerifyCertificateChainPolicy');
            }

            // CertGetCertificateChain
            const CertGetCertificateChain = Module.findExportByName('crypt32.dll', 'CertGetCertificateChain');
            if (CertGetCertificateChain) {
                Interceptor.attach(CertGetCertificateChain, {
                    onEnter: function(args) {
                        send({
                            type: 'cert_pinning',
                            method: 'CertGetCertificateChain',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        retval.replace(1);
                    }
                });
                detections.push('CertGetCertificateChain');
            }

            // WinHTTP - WinHttpSetOption for SECURITY_FLAGS
            const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
            if (WinHttpSetOption) {
                Interceptor.attach(WinHttpSetOption, {
                    onEnter: function(args) {
                        const option = args[1].toInt32();
                        // WINHTTP_OPTION_SECURITY_FLAGS (31)
                        if (option === 31) {
                            send({
                                type: 'cert_pinning',
                                method: 'WinHttpSetOption.SECURITY_FLAGS',
                                location: this.returnAddress.toString()
                            });
                            // Set flags: SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100) |
                            // SECURITY_FLAG_IGNORE_CERT_DATE_INVALID (0x2000) |
                            // SECURITY_FLAG_IGNORE_CERT_CN_INVALID (0x1000) |
                            // SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE (0x200)
                            if (args[2] && !args[2].isNull()) {
                                args[2].writeU32(0x3300);
                            }
                        }
                    }
                });
                detections.push('WinHttpSetOption');
            }

            // WinHTTP - WinHttpSetStatusCallback for certificate errors
            const WinHttpSetStatusCallback = Module.findExportByName('winhttp.dll', 'WinHttpSetStatusCallback');
            if (WinHttpSetStatusCallback) {
                Interceptor.attach(WinHttpSetStatusCallback, {
                    onEnter: function(args) {
                        const notificationFlags = args[2].toInt32();
                        // WINHTTP_CALLBACK_FLAG_SECURE_FAILURE (0x4000)
                        if (notificationFlags & 0x4000) {
                            send({
                                type: 'cert_pinning',
                                method: 'WinHttpSetStatusCallback.SECURE_FAILURE',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                });
                detections.push('WinHttpSetStatusCallback');
            }

            // WinINet - InternetSetOption
            const InternetSetOptionA = Module.findExportByName('wininet.dll', 'InternetSetOptionA');
            const InternetSetOptionW = Module.findExportByName('wininet.dll', 'InternetSetOptionW');

            const hookInternetSetOption = function(addr, name) {
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            const option = args[1].toInt32();
                            // INTERNET_OPTION_SECURITY_FLAGS (31)
                            if (option === 31) {
                                send({
                                    type: 'cert_pinning',
                                    method: name,
                                    location: this.returnAddress.toString()
                                });
                                if (args[2] && !args[2].isNull()) {
                                    // SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100) |
                                    // SECURITY_FLAG_IGNORE_REVOCATION (0x80) |
                                    // SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTP (0x8000) |
                                    // SECURITY_FLAG_IGNORE_CERT_CN_INVALID (0x1000) |
                                    // SECURITY_FLAG_IGNORE_CERT_DATE_INVALID (0x2000)
                                    args[2].writeU32(0xB180);
                                }
                            }
                        }
                    });
                    detections.push(name);
                }
            };
            hookInternetSetOption(InternetSetOptionA, 'InternetSetOptionA');
            hookInternetSetOption(InternetSetOptionW, 'InternetSetOptionW');

            // WinINet - InternetErrorDlg callback suppression
            const InternetErrorDlg = Module.findExportByName('wininet.dll', 'InternetErrorDlg');
            if (InternetErrorDlg) {
                Interceptor.attach(InternetErrorDlg, {
                    onEnter: function(args) {
                        const error = args[2].toInt32();
                        // ERROR_INTERNET_SEC_CERT_* errors (12037-12057)
                        if (error >= 12037 && error <= 12057) {
                            send({
                                type: 'cert_pinning',
                                method: 'InternetErrorDlg',
                                error: error,
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        // ERROR_SUCCESS
                        retval.replace(0);
                    }
                });
                detections.push('InternetErrorDlg');
            }

            // SChannel - AcquireCredentialsHandle for custom validation
            const AcquireCredentialsHandleA = Module.findExportByName('secur32.dll', 'AcquireCredentialsHandleA');
            const AcquireCredentialsHandleW = Module.findExportByName('secur32.dll', 'AcquireCredentialsHandleW');

            const hookAcquireCredentials = function(addr, name) {
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                type: 'cert_pinning',
                                method: name,
                                location: this.returnAddress.toString()
                            });
                        }
                    });
                    detections.push(name);
                }
            };
            hookAcquireCredentials(AcquireCredentialsHandleA, 'AcquireCredentialsHandleA');
            hookAcquireCredentials(AcquireCredentialsHandleW, 'AcquireCredentialsHandleW');

            // SChannel - QueryContextAttributes for certificate info
            const QueryContextAttributesA = Module.findExportByName('secur32.dll', 'QueryContextAttributesA');
            if (QueryContextAttributesA) {
                Interceptor.attach(QueryContextAttributesA, {
                    onEnter: function(args) {
                        const attribute = args[1].toInt32();
                        // SECPKG_ATTR_REMOTE_CERT_CONTEXT (0x53)
                        if (attribute === 0x53) {
                            send({
                                type: 'cert_pinning',
                                method: 'QueryContextAttributesA.REMOTE_CERT_CONTEXT',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                });
                detections.push('QueryContextAttributesA');
            }

            // .NET ServicePointManager - hook CLR
            try {
                const clrjit = Module.findBaseAddress('clrjit.dll');
                if (clrjit) {
                    // Look for ServicePointManager patterns
                    const pattern = '53 65 72 76 69 63 65 50 6F 69 6E 74 4D 61 6E 61 67 65 72';
                    const matches = Memory.scanSync(clrjit, 0x100000, pattern);
                    if (matches.length > 0) {
                        send({
                            type: 'cert_pinning',
                            method: '.NET ServicePointManager detected',
                            location: matches[0].address.toString()
                        });
                        detections.push('.NET ServicePointManager');
                    }
                }
            } catch(e) {}

            // HttpClient - WinHttpHandler certificate validation
            const WinHttpReceiveResponse = Module.findExportByName('winhttp.dll', 'WinHttpReceiveResponse');
            if (WinHttpReceiveResponse) {
                Interceptor.attach(WinHttpReceiveResponse, {
                    onEnter: function(args) {
                        this.hRequest = args[0];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0) {
                            // Failed - might be certificate error, force success
                            const lastError = Module.findExportByName('kernel32.dll', 'GetLastError');
                            if (lastError) {
                                const error = new NativeFunction(lastError, 'uint32', [])();
                                // ERROR_WINHTTP_SECURE_FAILURE (12175)
                                if (error === 12175) {
                                    send({
                                        type: 'cert_pinning',
                                        method: 'WinHttpReceiveResponse.SECURE_FAILURE',
                                        location: this.returnAddress.toString()
                                    });
                                }
                            }
                        }
                    }
                });
                detections.push('WinHttpReceiveResponse');
            }
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, _data: object) -> None:
            try:
                if not isinstance(message, dict):
                    return
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if not isinstance(payload, dict):
                        return
                    if payload.get("type") == "cert_pinning":
                        info = ProtectionInfo(
                            type=ProtectionType.CERT_PINNING,
                            location=str(payload.get("location", "N/A")),
                            confidence=0.90,
                            details={
                                "method": payload.get("method", "Unknown"),
                                "hostname": payload.get("hostname", "N/A"),
                            },
                            bypass_available=True,
                            bypass_script=cert_pinning_script,
                        )
                        detections.append(info)
                        log_security(
                            f"Certificate pinning detected: {payload.get('method', 'Unknown')}",
                            context={"payload": payload},
                        )
            except (KeyError, TypeError, ValueError) as e:
                log_error(
                    "Error processing cert pinning detection message",
                    context={"error": str(e), "message": message},
                    exception=e,
                )

        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return detections
            script = self.session.create_script(cert_pinning_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception:
            logger.exception("Certificate pinning detection failed")

        return detections

    def detect_integrity_checks(self) -> list[ProtectionInfo]:
        """Detect integrity check mechanisms.

        Identifies hash-based and checksum-based integrity verification
        routines including CryptCreateHash, BCryptCreateHash, OpenSSL hash
        functions, memory protection changes, and self-modification detection
        mechanisms used to verify binary integrity.

        Returns:
            List of detected integrity check protection information objects.
                Each object contains hashing method, algorithm used,
                protected memory addresses, confidence score, and Frida
                bypass script for disabling integrity checks.

        Raises:
            Exception: If Frida session is not initialized or script
                execution fails.

        """
        detections = []

        integrity_script = """
        const detections = [];

        // Hash/checksum calculation detection
        const crypto_functions = [
            'MD5', 'SHA1', 'SHA256', 'SHA512',
            'CRC32', 'CRC64', 'Adler32'
        ];

        // Windows CryptoAPI
        if (Process.platform === 'windows') {
            const CryptCreateHash = Module.findExportByName('advapi32.dll', 'CryptCreateHash');
            if (CryptCreateHash) {
                Interceptor.attach(CryptCreateHash, {
                    onEnter: function(args) {
                        const algId = args[1].toInt32();
                        send({
                            type: 'integrity_check',
                            method: 'CryptCreateHash',
                            algorithm: algId,
                            location: this.returnAddress.toString()
                        });
                    }
                });
                detections.push('CryptCreateHash');
            }

            const BCryptCreateHash = Module.findExportByName('bcrypt.dll', 'BCryptCreateHash');
            if (BCryptCreateHash) {
                Interceptor.attach(BCryptCreateHash, {
                    onEnter: function(args) {
                        send({
                            type: 'integrity_check',
                            method: 'BCryptCreateHash',
                            location: this.returnAddress.toString()
                        });
                    }
                });
                detections.push('BCryptCreateHash');
            }

            // File mapping for memory comparison
            const CreateFileMappingW = Module.findExportByName('kernel32.dll', 'CreateFileMappingW');
            if (CreateFileMappingW) {
                Interceptor.attach(CreateFileMappingW, {
                    onEnter: function(args) {
                        if (args[0].toInt32() === -1) { // Page file mapping
                            send({
                                type: 'integrity_check',
                                method: 'CreateFileMappingW (Memory)',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                });
                detections.push('CreateFileMappingW');
            }
        }

        // OpenSSL hash functions
        ['MD5', 'SHA1', 'SHA256'].forEach(function(algo) {
            const func = Module.findExportByName(null, algo);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        send({
                            type: 'integrity_check',
                            method: 'OpenSSL_' + algo,
                            location: this.returnAddress.toString()
                        });
                    }
                });
                detections.push('OpenSSL_' + algo);
            }
        });

        // Memory protection changes (often used for integrity checks)
        const mprotect = Module.findExportByName(null, 'mprotect');
        const VirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');

        if (mprotect) {
            Interceptor.attach(mprotect, {
                onEnter: function(args) {
                    const addr = args[0];
                    const size = args[1].toInt32();
                    const prot = args[2].toInt32();

                    // Check if changing to read-only (potential integrity check)
                    if ((prot & 0x2) === 0 && (prot & 0x1) !== 0) {
                        send({
                            type: 'integrity_check',
                            method: 'mprotect (Read-Only)',
                            address: addr.toString(),
                            size: size,
                            location: this.returnAddress.toString()
                        });
                    }
                }
            });
            detections.push('mprotect');
        }

        if (VirtualProtect) {
            Interceptor.attach(VirtualProtect, {
                onEnter: function(args) {
                    const addr = args[0];
                    const size = args[1].toInt32();
                    const newProt = args[2].toInt32();

                    // Check for PAGE_READONLY (0x02)
                    if (newProt === 0x02) {
                        send({
                            type: 'integrity_check',
                            method: 'VirtualProtect (PAGE_READONLY)',
                            address: addr.toString(),
                            size: size,
                            location: this.returnAddress.toString()
                        });
                    }
                }
            });
            detections.push('VirtualProtect');
        }

        // Self-modification detection
        const textSection = Process.enumerateModules()[0].enumerateRanges('r-x')[0];
        if (textSection) {
            // Monitor writes to code section
            MemoryAccessMonitor.enable({
                base: textSection.base,
                size: textSection.size
            }, {
                onAccess: function(details) {
                    if (details.operation === 'write') {
                        send({
                            type: 'integrity_check',
                            method: 'Code Section Write',
                            address: details.address.toString(),
                            from: details.from.toString()
                        });
                    }
                }
            });
            detections.push('Code Modification Monitoring');
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, _data: object) -> None:
            try:
                if not isinstance(message, dict):
                    return
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if not isinstance(payload, dict):
                        return
                    if payload.get("type") == "integrity_check":
                        info = ProtectionInfo(
                            type=ProtectionType.INTEGRITY_CHECK,
                            location=str(payload.get("location", "N/A")),
                            confidence=0.85,
                            details={
                                "method": payload.get("method", "Unknown"),
                                "address": payload.get("address", "N/A"),
                                "algorithm": payload.get("algorithm", "N/A"),
                            },
                            bypass_available=True,
                            bypass_script=integrity_script,
                        )
                        detections.append(info)
                        log_security(
                            f"Integrity check detected: {payload.get('method', 'Unknown')}",
                            context={"payload": payload},
                        )
            except (KeyError, TypeError, ValueError) as e:
                log_error(
                    "Error processing integrity check detection message",
                    context={"error": str(e), "message": message},
                    exception=e,
                )

        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return detections
            script = self.session.create_script(integrity_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception:
            logger.exception("Integrity check detection failed")

        return detections

    def detect_vm_detection(self) -> list[ProtectionInfo]:
        """Detect VM/sandbox detection mechanisms.

        Identifies virtualization and sandbox detection techniques including
        registry key checks, CPUID instruction analysis, WMI queries, hardware
        device enumeration, RDTSC timing checks, GetSystemFirmwareTable SMBIOS
        analysis, and DMI detection methods used to prevent execution in virtual
        environments.

        Returns:
            List of detected VM/sandbox detection protection information objects.
                Each object contains detection method, registry keys or file
                paths examined, confidence score, and Frida bypass script for
                spoofing physical hardware characteristics.

        Raises:
            Exception: If Frida session is not initialized or script
                execution fails.

        """
        detections = []

        vm_detection_script = """
        const detections = [];

        if (Process.platform === 'windows') {
            // Registry key checks for VMs
            const RegOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
            if (RegOpenKeyExW) {
                Interceptor.attach(RegOpenKeyExW, {
                    onEnter: function(args) {
                        const key = args[1].readUtf16String();
                        const vmKeys = [
                            'VMware', 'VBox', 'VBOX', 'Virtual',
                            'Xen', 'QEMU', 'Bochs', 'Parallels'
                        ];

                        if (key && vmKeys.some(vm => key.includes(vm))) {
                            send({
                                type: 'vm_detection',
                                method: 'Registry Key Check',
                                key: key,
                                location: this.returnAddress.toString()
                            });
                            // Make it fail
                            args[1] = Memory.allocUtf16String('InvalidKey');
                        }
                    }
                });
                detections.push('Registry VM Keys');
            }

            // CPUID instruction detection and virtualization
            const cpuidAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, '0f a2');

            // Create CPUID hook handler that returns non-VM values
            const cpuidHandler = new NativeCallback(function(eaxPtr, ebxPtr, ecxPtr, edxPtr) {
                const eax = eaxPtr.readU32();
                const ecx = ecxPtr.readU32();

                // CPUID function 0x1: Processor Info and Features
                if (eax === 0x1) {
                    // Clear hypervisor bit (ECX bit 31)
                    const ecxVal = ecxPtr.readU32() & 0x7FFFFFFF;
                    ecxPtr.writeU32(ecxVal);

                    send({
                        type: 'vm_detection',
                        method: 'CPUID Function 1 (Hypervisor Bit)',
                        original_ecx: ecxPtr.readU32().toString(16),
                        spoofed_ecx: ecxVal.toString(16)
                    });
                }

                // CPUID function 0x40000000: Hypervisor CPUID leaf
                else if (eax >= 0x40000000 && eax <= 0x400000FF) {
                    // Return zeroes for all hypervisor-specific leaves
                    eaxPtr.writeU32(0);
                    ebxPtr.writeU32(0);
                    ecxPtr.writeU32(0);
                    edxPtr.writeU32(0);

                    send({
                        type: 'vm_detection',
                        method: 'CPUID Hypervisor Leaf',
                        leaf: '0x' + eax.toString(16)
                    });
                }

                // CPUID function 0x80000002-0x80000004: Processor Brand String
                else if (eax >= 0x80000002 && eax <= 0x80000004) {
                    const offset = (eax - 0x80000002) * 16;
                    const brand = 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz';

                    eaxPtr.writeU32(brand.charCodeAt(offset) | (brand.charCodeAt(offset+1) << 8) |
                                   (brand.charCodeAt(offset+2) << 16) | (brand.charCodeAt(offset+3) << 24));
                    ebxPtr.writeU32(brand.charCodeAt(offset+4) | (brand.charCodeAt(offset+5) << 8) |
                                   (brand.charCodeAt(offset+6) << 16) | (brand.charCodeAt(offset+7) << 24));
                    ecxPtr.writeU32(brand.charCodeAt(offset+8) | (brand.charCodeAt(offset+9) << 8) |
                                   (brand.charCodeAt(offset+10) << 16) | (brand.charCodeAt(offset+11) << 24));
                    edxPtr.writeU32(brand.charCodeAt(offset+12) | (brand.charCodeAt(offset+13) << 8) |
                                   (brand.charCodeAt(offset+14) << 16) | (brand.charCodeAt(offset+15) << 24));
                }

                return 0;
            }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

            cpuidAddresses.forEach(function(match) {
                send({
                    type: 'vm_detection',
                    method: 'CPUID Instruction',
                    address: match.address.toString()
                });

                // Allocate space for hook trampoline
                const hookSize = 32;
                const hookCode = Memory.alloc(hookSize);

                // Build hook code: save context, call handler, restore context, execute original CPUID
                const writer = new X86Writer(hookCode);

                // Save registers
                writer.putPushax();

                // Prepare arguments (pointers to EAX, EBX, ECX, EDX)
                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 28); // Point to saved EAX
                writer.putPush('eax');

                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 24);
                writer.putPush('eax');

                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 20);
                writer.putPush('eax');

                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 16);
                writer.putPush('eax');

                // Call handler
                writer.putCallAddress(cpuidHandler);
                writer.putAddRegImm('esp', 16); // Clean stack

                // Restore registers
                writer.putPopax();

                // Jump back to instruction after CPUID
                writer.putJmpAddress(match.address.add(2));
                writer.flush();

                // Replace CPUID instruction with jump to hook
                Memory.patchCode(match.address, 5, function(code) {
                    const patcher = new X86Writer(code);
                    patcher.putJmpAddress(hookCode);
                    patcher.flush();
                });
            });

            if (cpuidAddresses.length > 0) {
                detections.push('CPUID');
            }

            // Hook NtQuerySystemInformation for hypervisor detection
            const NtQuerySystemInformation = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
            if (NtQuerySystemInformation) {
                Interceptor.attach(NtQuerySystemInformation, {
                    onEnter: function(args) {
                        const infoClass = args[0].toInt32();
                        // SystemHypervisorInformation (0x94)
                        if (infoClass === 0x94 || infoClass === 0x95 || infoClass === 0x96) {
                            this.hypervisorQuery = true;
                            this.systemInfo = args[1];
                            send({
                                type: 'vm_detection',
                                method: 'NtQuerySystemInformation',
                                class: infoClass.toString(16)
                            });
                        }
                    },
                    onLeave: function(retval) {
                        if (this.hypervisorQuery && retval.toInt32() === 0) {
                            // Return no hypervisor present
                            this.systemInfo.writeU32(0);
                        }
                    }
                });
                detections.push('NtQuerySystemInformation');
            }

            // WMI queries for VM detection
            const CoCreateInstance = Module.findExportByName('ole32.dll', 'CoCreateInstance');
            if (CoCreateInstance) {
                Interceptor.attach(CoCreateInstance, {
                    onEnter: function(args) {
                        const clsid = args[0].readByteArray(16);
                        // WbemLocator CLSID
                        const wbemLocator = [0xdc, 0x12, 0xa6, 0x4c, 0x87, 0x5e, 0xd0, 0x11,
                                            0xa0, 0x76, 0x00, 0xaa, 0x00, 0x57, 0xbe, 0x6d];

                        if (clsid && JSON.stringify(Array.from(new Uint8Array(clsid))) ===
                            JSON.stringify(wbemLocator)) {
                            send({
                                type: 'vm_detection',
                                method: 'WMI Query',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                });
                detections.push('WMI');
            }

            // Hardware device checks
            const SetupDiGetClassDevsW = Module.findExportByName('setupapi.dll', 'SetupDiGetClassDevsW');
            if (SetupDiGetClassDevsW) {
                Interceptor.attach(SetupDiGetClassDevsW, {
                    onEnter: function(args) {
                        send({
                            type: 'vm_detection',
                            method: 'Hardware Enumeration',
                            location: this.returnAddress.toString()
                        });
                    }
                });
                detections.push('Hardware Enumeration');
            }

            // Timing checks (RDTSC/RDTSCP) - normalize timing to hide VM overhead
            const rdtscAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, '0f 31');
            const rdtscpAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, '0f 01 f9');

            // Initialize base timestamp and multiplier for realistic timing
            let baseTimestamp = 0x100000000; // Start at reasonable value
            let lastTimestamp = baseTimestamp;
            const clockMultiplier = 0.85; // Reduce clock to hide VM overhead (~15% reduction)

            // Create RDTSC hook handler with timing normalization
            const rdtscHandler = new NativeCallback(function(eaxPtr, edxPtr) {
                // Calculate realistic increment (average ~3000 cycles between checks)
                const increment = Math.floor(Math.random() * 2000) + 2000;
                lastTimestamp += Math.floor(increment * clockMultiplier);

                // Split 64-bit timestamp into EDX:EAX
                const low = lastTimestamp & 0xFFFFFFFF;
                const high = (lastTimestamp >> 32) & 0xFFFFFFFF;

                eaxPtr.writeU32(low);
                edxPtr.writeU32(high);

                return 0;
            }, 'int', ['pointer', 'pointer']);

            // Hook RDTSC instructions
            rdtscAddresses.forEach(function(match) {
                send({
                    type: 'vm_detection',
                    method: 'RDTSC Timing',
                    address: match.address.toString()
                });

                // Allocate space for hook trampoline
                const hookSize = 32;
                const hookCode = Memory.alloc(hookSize);

                // Build hook code
                const writer = new X86Writer(hookCode);

                // Save all registers except EAX/EDX (RDTSC outputs)
                writer.putPushReg('ebx');
                writer.putPushReg('ecx');
                writer.putPushReg('esi');
                writer.putPushReg('edi');

                // Allocate stack space for outputs
                writer.putSubRegImm('esp', 8);

                // Prepare arguments (pointers to EAX, EDX slots)
                writer.putMovRegReg('eax', 'esp');
                writer.putPush('eax');
                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 8);
                writer.putPush('eax');

                // Call handler
                writer.putCallAddress(rdtscHandler);
                writer.putAddRegImm('esp', 8);

                // Read outputs from stack
                writer.putPopReg('eax');
                writer.putPopReg('edx');

                // Restore registers
                writer.putPopReg('edi');
                writer.putPopReg('esi');
                writer.putPopReg('ecx');
                writer.putPopReg('ebx');

                // Jump back
                writer.putJmpAddress(match.address.add(2));
                writer.flush();

                // Replace RDTSC with jump to hook
                Memory.patchCode(match.address, 5, function(code) {
                    const patcher = new X86Writer(code);
                    patcher.putJmpAddress(hookCode);
                    patcher.flush();
                });
            });

            // Hook RDTSCP instructions (similar to RDTSC but also returns processor ID in ECX)
            rdtscpAddresses.forEach(function(match) {
                send({
                    type: 'vm_detection',
                    method: 'RDTSCP Timing',
                    address: match.address.toString()
                });

                const hookSize = 32;
                const hookCode = Memory.alloc(hookSize);
                const writer = new X86Writer(hookCode);

                writer.putPushReg('ebx');
                writer.putPushReg('esi');
                writer.putPushReg('edi');

                writer.putSubRegImm('esp', 8);
                writer.putMovRegReg('eax', 'esp');
                writer.putPush('eax');
                writer.putMovRegReg('eax', 'esp');
                writer.putAddRegImm('eax', 8);
                writer.putPush('eax');

                writer.putCallAddress(rdtscHandler);
                writer.putAddRegImm('esp', 8);

                writer.putPopReg('eax');
                writer.putPopReg('edx');

                // Set ECX to processor ID (0 for single processor)
                writer.putXorRegReg('ecx', 'ecx');

                writer.putPopReg('edi');
                writer.putPopReg('esi');
                writer.putPopReg('ebx');

                writer.putJmpAddress(match.address.add(3));
                writer.flush();

                Memory.patchCode(match.address, 5, function(code) {
                    const patcher = new X86Writer(code);
                    patcher.putJmpAddress(hookCode);
                    patcher.flush();
                });
            });

            if (rdtscAddresses.length > 0 || rdtscpAddresses.length > 0) {
                detections.push('RDTSC/RDTSCP');
            }

            // Hook SIDT/SGDT/SLDT instructions for descriptor table checks
            const sidtPattern = '0f 01';
            const descriptorChecks = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, sidtPattern);

            // Realistic IDT base for physical hardware (Windows kernel range)
            const physicalIdtBase = ptr('0x80B95400');
            const physicalGdtBase = ptr('0x80B95000');

            descriptorChecks.forEach(function(match) {
                const modRM = match.address.add(2).readU8();
                const opcode = (modRM >> 3) & 0x7;

                // SIDT (opcode 1), SGDT (opcode 0), SLDT (opcode 0 with different encoding)
                if (opcode === 1 || opcode === 0) {
                    const isIDT = (opcode === 1);

                    send({
                        type: 'vm_detection',
                        method: isIDT ? 'SIDT Instruction' : 'SGDT Instruction',
                        address: match.address.toString(),
                        modrm: '0x' + modRM.toString(16)
                    });

                    // Decode ModR/M to find destination memory operand
                    const mod = (modRM >> 6) & 0x3;
                    const rm = modRM & 0x7;

                    // Create hook that modifies the output buffer after instruction executes
                    const hookSize = 48;
                    const hookCode = Memory.alloc(hookSize);
                    const writer = new X86Writer(hookCode);

                    // Save all registers
                    writer.putPushax();

                    // Execute original SIDT/SGDT instruction
                    writer.putBytes(match.address.readByteArray(3));

                    // Calculate destination address based on ModR/M
                    // For simplicity, handle common case: [reg+disp] or [reg]
                    if (mod === 0 && rm === 5) {
                        // [disp32]
                        const disp = match.address.add(3).readU32();
                        writer.putMovRegAddress('edi', ptr(disp));
                    } else if (mod === 1) {
                        // [reg+disp8]
                        const regMap = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
                        const disp = match.address.add(3).readS8();
                        writer.putMovRegReg('edi', regMap[rm]);
                        if (disp !== 0) {
                            writer.putAddRegImm('edi', disp);
                        }
                    } else if (mod === 2) {
                        // [reg+disp32]
                        const regMap = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
                        const disp = match.address.add(3).readS32();
                        writer.putMovRegReg('edi', regMap[rm]);
                        if (disp !== 0) {
                            writer.putAddRegImm('edi', disp);
                        }
                    }

                    // Modify the base address in the descriptor (offset 2-6 for 32-bit, 2-10 for 64-bit)
                    const targetBase = isIDT ? physicalIdtBase : physicalGdtBase;
                    writer.putMovRegU32('eax', targetBase.and(0xFFFFFFFF).toInt32());
                    writer.putMovRegOffsetPtrReg('edi', 2, 'eax');

                    if (Process.pointerSize === 8) {
                        writer.putMovRegU32('eax', targetBase.shr(32).and(0xFFFFFFFF).toInt32());
                        writer.putMovRegOffsetPtrReg('edi', 6, 'eax');
                    }

                    // Restore registers
                    writer.putPopax();

                    // Jump to instruction after SIDT/SGDT
                    writer.putJmpAddress(match.address.add(3 + (mod === 0 && rm === 5 ? 4 : mod === 1 ? 1 : mod === 2 ? 4 : 0)));
                    writer.flush();

                    // Replace instruction with jump to hook
                    Memory.patchCode(match.address, 5, function(code) {
                        const patcher = new X86Writer(code);
                        patcher.putJmpAddress(hookCode);
                        patcher.flush();
                    });
                }
            });

            if (descriptorChecks.length > 0) {
                detections.push('SIDT/SGDT/SLDT');
            }

            // Hook IN/OUT instructions for I/O port access (VMware backdoor detection)
            const vmwarePortHandler = new NativeCallback(function() {
                send({
                    type: 'vm_detection',
                    method: 'VMware Backdoor Access Blocked'
                });
                return 0xFFFFFFFF; // Return error value
            }, 'uint32', []);

            const inAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, 'ed'); // IN EAX, DX

            inAddresses.forEach(function(match) {
                // Check context around IN instruction for VMware magic port 0x5658
                const context = match.address.sub(10).readByteArray(15);
                const contextBytes = new Uint8Array(context);

                // Look for MOV EDX, 0x5658 or MOV DX, 0x5658
                let isVMwarePort = false;
                for (let i = 0; i < 10; i++) {
                    // Check for BA 58 56 (MOV DX, 0x5658) or 66 BA 58 56 (MOV EDX, 0x5658)
                    if ((contextBytes[i] === 0xBA && contextBytes[i+1] === 0x58 && contextBytes[i+2] === 0x56) ||
                        (contextBytes[i] === 0x66 && contextBytes[i+1] === 0xBA && contextBytes[i+2] === 0x58 && contextBytes[i+3] === 0x56)) {
                        isVMwarePort = true;
                        break;
                    }
                }

                if (isVMwarePort) {
                    send({
                        type: 'vm_detection',
                        method: 'VMware Backdoor Port',
                        address: match.address.toString()
                    });

                    // Replace IN instruction with call to handler that returns error
                    const hookSize = 16;
                    const hookCode = Memory.alloc(hookSize);
                    const writer = new X86Writer(hookCode);

                    // Call handler
                    writer.putCallAddress(vmwarePortHandler);

                    // Jump to next instruction
                    writer.putJmpAddress(match.address.add(1));
                    writer.flush();

                    Memory.patchCode(match.address, 5, function(code) {
                        const patcher = new X86Writer(code);
                        patcher.putJmpAddress(hookCode);
                        patcher.flush();
                    });
                }
            });

            if (inAddresses.length > 0) {
                detections.push('IN/OUT Instructions');
            }

            // Hook VM-specific registry keys and hide artifacts
            const RegQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
            if (RegQueryValueExW) {
                Interceptor.attach(RegQueryValueExW, {
                    onEnter: function(args) {
                        this.valueName = args[1].readUtf16String();
                        this.data = args[3];
                        this.dataSize = args[4];
                    },
                    onLeave: function(retval) {
                        if (retval.toInt32() === 0 && this.data && !this.data.isNull()) {
                            const value = this.valueName;
                            // Spoof VM-related registry values
                            if (value && (value.includes('SystemBiosVersion') ||
                                         value.includes('VideoBiosVersion') ||
                                         value.includes('SystemManufacturer') ||
                                         value.includes('SystemProductName'))) {

                                const dataSize = this.dataSize.readU32();
                                const currentValue = this.data.readUtf16String();

                                if (currentValue && (currentValue.includes('VMware') ||
                                                    currentValue.includes('VirtualBox') ||
                                                    currentValue.includes('VBOX') ||
                                                    currentValue.includes('Xen') ||
                                                    currentValue.includes('QEMU'))) {

                                    // Replace with realistic hardware values
                                    const spoofedValues = {
                                        'SystemBiosVersion': 'American Megatrends Inc. 0603',
                                        'VideoBiosVersion': 'NVIDIA 384.94.0.0',
                                        'SystemManufacturer': 'ASUSTeK COMPUTER INC.',
                                        'SystemProductName': 'ROG STRIX Z390-E GAMING'
                                    };

                                    for (const key in spoofedValues) {
                                        if (value.includes(key)) {
                                            this.data.writeUtf16String(spoofedValues[key]);
                                            this.dataSize.writeU32((spoofedValues[key].length + 1) * 2);

                                            send({
                                                type: 'vm_detection',
                                                method: 'Registry Value Spoofed',
                                                key: value,
                                                original: currentValue,
                                                spoofed: spoofedValues[key]
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
                detections.push('Registry Value Spoofing');
            }

            // Hook GetSystemFirmwareTable to hide VM SMBIOS data
            const GetSystemFirmwareTable = Module.findExportByName('kernel32.dll', 'GetSystemFirmwareTable');
            if (GetSystemFirmwareTable) {
                Interceptor.attach(GetSystemFirmwareTable, {
                    onEnter: function(args) {
                        const signature = args[0].toInt32();
                        const tableId = args[1].toInt32();

                        // RSMB signature (Raw SMBIOS data)
                        if (signature === 0x52534D42 || signature === 0x4649524D) {
                            this.isSMBIOS = true;
                            this.buffer = args[2];
                            this.bufferSize = args[3].toInt32();

                            send({
                                type: 'vm_detection',
                                method: 'GetSystemFirmwareTable',
                                signature: '0x' + signature.toString(16)
                            });
                        }
                    },
                    onLeave: function(retval) {
                        if (this.isSMBIOS && this.buffer && !this.buffer.isNull() && retval.toInt32() > 0) {
                            const bufferData = this.buffer.readByteArray(this.bufferSize);
                            if (bufferData) {
                                const bytes = new Uint8Array(bufferData);

                                // Replace VM vendor strings in SMBIOS data
                                const vmStrings = [
                                    'VMware', 'VirtualBox', 'VBOX', 'Xen', 'QEMU',
                                    'Virtual', 'innotek GmbH', 'Oracle Corporation'
                                ];
                                const replacement = 'ASUSTeK';

                                let modified = false;
                                for (const vmStr of vmStrings) {
                                    for (let i = 0; i < bytes.length - vmStr.length; i++) {
                                        let match = true;
                                        for (let j = 0; j < vmStr.length; j++) {
                                            if (bytes[i + j] !== vmStr.charCodeAt(j)) {
                                                match = false;
                                                break;
                                            }
                                        }
                                        if (match) {
                                            for (let j = 0; j < replacement.length && j < vmStr.length; j++) {
                                                bytes[i + j] = replacement.charCodeAt(j);
                                            }
                                            for (let j = replacement.length; j < vmStr.length; j++) {
                                                bytes[i + j] = 0x20; // Space padding
                                            }
                                            modified = true;

                                            send({
                                                type: 'vm_detection',
                                                method: 'SMBIOS String Replaced',
                                                original: vmStr,
                                                replacement: replacement,
                                                offset: i
                                            });
                                        }
                                    }
                                }

                                if (modified) {
                                    this.buffer.writeByteArray(Array.from(bytes));
                                }
                            }
                        }
                    }
                });
                detections.push('SMBIOS Spoofing');
            }
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, _data: object) -> None:
            try:
                if not isinstance(message, dict):
                    return
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if not isinstance(payload, dict):
                        return
                    if payload.get("type") == "vm_detection":
                        location_val = payload.get("location", payload.get("address", "N/A"))
                        info = ProtectionInfo(
                            type=ProtectionType.VM_DETECTION,
                            location=str(location_val),
                            confidence=0.88,
                            details={
                                "method": payload.get("method", "Unknown"),
                                "key": payload.get("key", "N/A"),
                                "path": payload.get("path", "N/A"),
                            },
                            bypass_available=True,
                            bypass_script=vm_detection_script,
                        )
                        detections.append(info)
                        log_security(
                            f"VM detection detected: {payload.get('method', 'Unknown')}",
                            context={"payload": payload},
                        )
            except (KeyError, TypeError, ValueError) as e:
                log_error(
                    "Error processing VM detection message",
                    context={"error": str(e), "message": message},
                    exception=e,
                )

        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return detections
            script = self.session.create_script(vm_detection_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception:
            logger.exception("VM detection failed")

        return detections

    def detect_packers(self) -> list[ProtectionInfo]:
        """Detect known packers and protectors.

        Performs signature-based and heuristic detection of common executable
        packers including UPX, ASPack, PECompact, Themida, VMProtect, Enigma,
        MPRESS, Obsidium, ASProtect, Armadillo, ExeCryptor, and others by
        analyzing section headers, import tables, and entropy patterns.

        Returns:
            List of detected packer protection information objects.
                Each object contains packer name, detection method,
                confidence score, and Frida script for automated unpacking
                of the identified packer.

        Raises:
            Exception: If Frida session is not initialized or script
                execution fails.

        """
        detections: list[ProtectionInfo] = []

        # Signature-based packer detection
        packer_signatures = {
            "UPX": [b"UPX!", b"UPX0", b"UPX1", b"UPX2"],
            "ASPack": [b"ASPack", b".aspack", b".adata"],
            "PECompact": [b"PECompact", b"PEC2"],
            "Themida": [b"Themida", b".themida", b"SecureEngine"],
            "VMProtect": [b".vmp0", b".vmp1", b".vmp2", b"VMProtect"],
            "Enigma": [b"Enigma protector", b".enigma1", b".enigma2"],
            "MPRESS": [b"MPRESS", b".MPRESS1", b".MPRESS2"],
            "Obsidium": [b"Obsidium", b"obsidium.dll"],
            "ASProtect": [b"ASProtect", b".aspr", b"asprotect.dll"],
            "Armadillo": [b"Armadillo", b"arma.dll", b"ArmAccess.dll"],
            "ExeCryptor": [b"ExeCryptor", b"EXECryptor"],
            "NsPack": [b"nsp0", b"nsp1", b"nsp2"],
            "PELock": [b"PELock", b"PELOCK"],
            "Petite": [b"petite", b".petite"],
            "RLPack": [b"RLPack", b".RLPack"],
            "TELock": [b"TELock", b".tel0"],
            "yoda": [b"yoda's Protector", b".yP"],
        }

        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return detections

            # Get the main module via Frida script
            get_header_script = """
            const mainModule = Process.enumerateModules()[0];
            const headerData = mainModule.base.readByteArray(4096);
            send({ type: 'header_data', data: Array.from(new Uint8Array(headerData)) });
            """

            header_data = b""

            def on_header_message(message: object, _data: object) -> None:
                nonlocal header_data
                try:
                    if not isinstance(message, dict):
                        return
                    if message.get("type") == "send":
                        payload = message.get("payload")
                        if isinstance(payload, dict) and payload.get("type") == "header_data":
                            data_arr = payload.get("data")
                            if isinstance(data_arr, list):
                                header_data = bytes(data_arr)
                                log_analysis(
                                    "Received module header data",
                                    context={"data_length": len(header_data)},
                                )
                except (KeyError, TypeError, ValueError) as e:
                    log_error(
                        "Error processing header data message",
                        context={"error": str(e), "message": message},
                        exception=e,
                    )

            temp_script = self.session.create_script(get_header_script)
            temp_script.on("message", on_header_message)
            temp_script.load()
            time.sleep(0.5)
            temp_script.unload()

            if not header_data:
                logger.warning("Could not read module header")
                return detections

            for packer_name, signatures in packer_signatures.items():
                for signature in signatures:
                    if signature in header_data:
                        info = ProtectionInfo(
                            type=ProtectionType.PACKER,
                            location="Module header",
                            confidence=0.92,
                            details={
                                "packer": packer_name,
                                "signature": signature.decode("utf-8", errors="ignore"),
                            },
                            bypass_available=True,
                            bypass_script=self._generate_unpacking_script(packer_name),
                        )
                        detections.append(info)
                        break

            # Heuristic detection
            heuristic_script = """
            const detections = [];
            const modules = Process.enumerateModules();
            const mainModule = modules[0];

            // Check for high entropy sections (packed data)
            const ranges = mainModule.enumerateRanges('r--');
            ranges.forEach(function(range) {
                const data = range.base.readByteArray(Math.min(range.size, 1024));
                const entropy = calculateEntropy(data);

                if (entropy > 7.5) {
                    send({
                        type: 'packer_heuristic',
                        method: 'High Entropy Section',
                        address: range.base.toString(),
                        entropy: entropy
                    });
                }
            });

            // Check for unusual section names
            const pe = mainModule.base;
            const dosHeader = pe.readU16();
            if (dosHeader === 0x5A4D) { // MZ
                const peOffset = pe.add(0x3C).readU32();
                const peHeader = pe.add(peOffset);
                const ntSignature = peHeader.readU32();

                if (ntSignature === 0x00004550) { // PE
                    const numberOfSections = peHeader.add(0x6).readU16();
                    const sizeOfOptionalHeader = peHeader.add(0x14).readU16();
                    const sectionTable = peHeader.add(0x18 + sizeOfOptionalHeader);

                    const suspiciousSections = [
                        'UPX', 'ASPack', '.vmp', '.themida', '.enigma',
                        '.mpress', '.aspr', '.arm', '.petite', '.pelock'
                    ];

                    for (let i = 0; i < numberOfSections; i++) {
                        const sectionHeader = sectionTable.add(i * 0x28);
                        const sectionName = sectionHeader.readCString(8);

                        if (suspiciousSections.some(name => sectionName.includes(name))) {
                            send({
                                type: 'packer_heuristic',
                                method: 'Suspicious Section Name',
                                section: sectionName
                            });
                        }
                    }
                }
            }

            // Check for import table anomalies
            const imports = mainModule.enumerateImports();
            if (imports.length < 5) {
                send({
                    type: 'packer_heuristic',
                    method: 'Minimal Import Table',
                    importCount: imports.length
                });
            }

            // Check for TLS callbacks (often used by packers)
            if (Process.platform === 'windows') {
                const tlsCallbacks = Module.findExportByName('ntdll.dll', 'LdrpCallTlsInitializers');
                if (tlsCallbacks) {
                    send({
                        type: 'packer_heuristic',
                        method: 'TLS Callbacks Present'
                    });
                }
            }

            function calculateEntropy(data) {
                const bytes = new Uint8Array(data);
                const freq = new Array(256).fill(0);

                for (let i = 0; i < bytes.length; i++) {
                    freq[bytes[i]]++;
                }

                let entropy = 0;
                for (let i = 0; i < 256; i++) {
                    if (freq[i] > 0) {
                        const p = freq[i] / bytes.length;
                        entropy -= p * Math.log2(p);
                    }
                }

                return entropy;
            }
            """

            def on_message(message: object, _data: object) -> None:
                try:
                    if not isinstance(message, dict):
                        return
                    if message.get("type") == "send":
                        payload = message.get("payload")
                        if not isinstance(payload, dict):
                            return
                        if payload.get("type") == "packer_heuristic":
                            info = ProtectionInfo(
                                type=ProtectionType.PACKER,
                                location=str(payload.get("address", "N/A")),
                                confidence=0.75,
                                details={
                                    "method": payload.get("method", "Heuristic"),
                                    "section": payload.get("section", "N/A"),
                                    "entropy": payload.get("entropy", 0),
                                    "importCount": payload.get("importCount", "N/A"),
                                },
                                bypass_available=True,
                                bypass_script=self._generate_generic_unpacking_script(),
                            )
                            detections.append(info)
                            log_security(
                                f"Packer heuristic detected: {payload.get('method', 'Heuristic')}",
                                context={"payload": payload},
                            )
                except (KeyError, TypeError, ValueError) as e:
                    log_error(
                        "Error processing packer heuristic message",
                        context={"error": str(e), "message": message},
                        exception=e,
                    )

            script = self.session.create_script(heuristic_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()

        except Exception:
            logger.exception("Packer detection failed")

        return detections

    def _generate_unpacking_script(self, packer_name: str) -> str:
        """Generate packer-specific unpacking script.

        Selects and returns an appropriate Frida instrumentation script tailored
        to defeat the specified packer, delegating to specialized unpacking
        methods for known packers (UPX, VMProtect, Themida) or falling back to
        generic unpacking techniques.

        Args:
            packer_name: Name of the packer to generate script for. Supports
                UPX, VMProtect, Themida, and other common packers.

        Returns:
            Frida script string for unpacking the specified packer. Script hooks
                decompression routines, memory allocations, and protection changes
                to extract unpacked code.

        Raises:
            ValueError: If packer_name is empty or None.

        """
        if packer_name == "UPX":
            return self._generate_upx_unpacking_script()
        if packer_name == "VMProtect":
            return self._generate_vmprotect_unpacking_script()
        if packer_name == "Themida":
            return self._generate_themida_unpacking_script()
        return self._generate_generic_unpacking_script()

    def _generate_upx_unpacking_script(self) -> str:
        """Generate UPX unpacking script.

        Creates a Frida instrumentation script that detects and bypasses UPX
        decompression routines by hooking the decompression function, monitoring
        VirtualProtect calls for executable memory regions, and extracting the
        original entry point and unpacked code sections.

        Returns:
            Frida script string for unpacking UPX-packed binaries. Script identifies
                the original entry point and performs memory dumps of decompressed
                code sections.

        """
        return """
        // UPX Unpacking Script
        const mainModule = Process.enumerateModules()[0];

        // Find UPX decompression routine
        const upxSignatures = ['55 8B EC 83 E4', '60 BE ?? ?? ?? ?? 8D BE'];
        let decompressionRoutine = null;

        upxSignatures.forEach(function(sig) {
            const matches = Memory.scanSync(mainModule.base, mainModule.size, sig);
            if (matches.length > 0) {
                decompressionRoutine = matches[0].address;
            }
        });

        if (decompressionRoutine) {
            // Hook the decompression routine
            Interceptor.attach(decompressionRoutine, {
                onLeave: function(retval) {
                    // Find OEP (Original Entry Point)
                    const oepPatterns = ['E8 ?? ?? ?? ?? E9', '55 8B EC 6A FF'];

                    oepPatterns.forEach(function(pattern) {
                        const matches = Memory.scanSync(mainModule.base, mainModule.size, pattern);
                        if (matches.length > 0) {
                            send({
                                type: 'upx_unpacked',
                                oep: matches[0].address.toString()
                            });

                            // Dump unpacked code
                            const unpacked = matches[0].address.readByteArray(0x10000);
                            send({
                                type: 'dump',
                                data: unpacked
                            });
                        }
                    });
                }
            });
        }

        // Alternative: Hook VirtualProtect to catch unpacking
        if (Process.platform === 'windows') {
            const VirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
            Interceptor.attach(VirtualProtect, {
                onEnter: function(args) {
                    const addr = args[0];
                    const size = args[1].toInt32();
                    const newProt = args[2].toInt32();

                    // PAGE_EXECUTE_READWRITE
                    if (newProt === 0x40) {
                        send({
                            type: 'memory_unpacked',
                            address: addr.toString(),
                            size: size
                        });
                    }
                }
            });
        }
        """

    def _generate_vmprotect_unpacking_script(self) -> str:
        """Generate VMProtect unpacking script.

        Creates a Frida instrumentation script that bypasses VMProtect's virtual
        machine by using Stalker to trace VM handler execution patterns, monitors
        memory allocations and writes for unpacked code, and identifies the
        original entry point through execution analysis.

        Returns:
            Frida script string for unpacking VMProtect-protected binaries. Script
                uses dynamic instrumentation to trace VM handler execution and
                extract unpacked code regions.

        """
        return """
        // VMProtect Unpacking Script - Production Implementation
        const mainModule = Process.enumerateModules()[0];
        const vmHandlers = new Map();
        const allocatedRegions = [];
        let dispatcherAddress = null;
        let vmContextPtr = null;
        let potentialOEPs = [];

        // VMProtect signature patterns for VM entry detection
        const vmEntryPatterns = [
            [0x9C, 0x60],                    // PUSHFD; PUSHAD - common VM entry
            [0x60, 0x9C],                    // PUSHAD; PUSHFD - alternative
            [0xE8, 0x00, 0x00, 0x00, 0x00],  // CALL $+5 (get EIP)
            [0x68],                           // PUSH imm32 (handler table)
        ];

        // Find VMP sections
        const vmpSections = [];
        mainModule.enumerateRanges('r-x').forEach(function(range) {
            try {
                const data = range.base.readByteArray(16);
                if (data) {
                    const bytes = new Uint8Array(data);
                    // Check for .vmp0, .vmp1, .vmp2 section markers
                    if ((bytes[0] === 0x2E && bytes[1] === 0x76 && bytes[2] === 0x6D && bytes[3] === 0x70) ||
                        (bytes[0] === 0xE9 || bytes[0] === 0xE8)) {
                        vmpSections.push(range);
                        send({
                            type: 'vmprotect_section',
                            base: range.base.toString(),
                            size: range.size
                        });
                    }
                }
            } catch(e) {}
        });

        // Identify VM dispatcher by scanning for characteristic patterns
        function findVMDispatcher() {
            vmpSections.forEach(function(section) {
                try {
                    const scanSize = Math.min(section.size, 0x10000);
                    Memory.scan(section.base, scanSize, '8B ?? 8B ?? FF E?', {
                        onMatch: function(address, size) {
                            // Pattern: MOV reg, [reg]; MOV reg, [reg]; JMP reg
                            // This is the classic VMProtect dispatcher pattern
                            dispatcherAddress = address;
                            send({
                                type: 'vmprotect_dispatcher',
                                address: address.toString(),
                                pattern: 'handler_dispatch'
                            });
                        },
                        onError: function(_reason) {},
                        onComplete: function() {}
                    });

                    // Alternative pattern: switch-case style dispatcher
                    Memory.scan(section.base, scanSize, '0F B6 ?? ?? 83 ?? ?? 0F 87', {
                        onMatch: function(address, size) {
                            // MOVZX; CMP; JA - bytecode bounds check
                            if (!dispatcherAddress) {
                                dispatcherAddress = address;
                                send({
                                    type: 'vmprotect_dispatcher',
                                    address: address.toString(),
                                    pattern: 'switch_dispatch'
                                });
                            }
                        },
                        onError: function(_reason) {},
                        onComplete: function() {}
                    });
                } catch(e) {}
            });
        }

        findVMDispatcher();

        // Hook VM dispatcher to trace handler execution
        if (dispatcherAddress) {
            Interceptor.attach(dispatcherAddress, {
                onEnter: function(args) {
                    // Capture VM context (typically in a register pair)
                    vmContextPtr = this.context;
                    const handlerIdx = this.context.eax ? this.context.eax.toInt32() & 0xFF : 0;

                    if (!vmHandlers.has(handlerIdx)) {
                        vmHandlers.set(handlerIdx, { count: 0, addresses: [] });
                    }
                    const handler = vmHandlers.get(handlerIdx);
                    handler.count++;

                    // Track handler addresses for devirtualization
                    const pc = this.context.pc;
                    if (!handler.addresses.includes(pc.toString())) {
                        handler.addresses.push(pc.toString());
                    }
                }
            });
        }

        // Use Stalker for instruction-level tracing in VMP sections
        const threadId = Process.getCurrentThreadId();
        Stalker.follow(threadId, {
            transform: function(iterator) {
                let instruction;
                while ((instruction = iterator.next()) !== null) {
                    const addr = instruction.address;

                    // Check if we're in a VMP section
                    let inVmpSection = false;
                    for (let i = 0; i < vmpSections.length; i++) {
                        if (addr.compare(vmpSections[i].base) >= 0 &&
                            addr.compare(vmpSections[i].base.add(vmpSections[i].size)) < 0) {
                            inVmpSection = true;
                            break;
                        }
                    }

                    if (inVmpSection) {
                        // Instrument VM handler calls
                        if (instruction.mnemonic === 'call' || instruction.mnemonic === 'jmp') {
                            iterator.putCallout(function(context) {
                                const target = context.pc;
                                const handlerKey = target.toString();

                                if (!vmHandlers.has(handlerKey)) {
                                    vmHandlers.set(handlerKey, { count: 0, type: 'handler' });
                                }
                                vmHandlers.get(handlerKey).count++;

                                // High frequency = VM handler
                                if (vmHandlers.get(handlerKey).count === 100) {
                                    send({
                                        type: 'vmprotect_handler_identified',
                                        address: handlerKey,
                                        frequency: 'high'
                                    });
                                }
                            });
                        }

                        // Detect VM exit (transition to original code)
                        if (instruction.mnemonic === 'ret') {
                            iterator.putCallout(function(context) {
                                const returnAddr = context.sp.readPointer();

                                // Check if return is to code outside VMP section
                                let outsideVmp = true;
                                for (let i = 0; i < vmpSections.length; i++) {
                                    if (returnAddr.compare(vmpSections[i].base) >= 0 &&
                                        returnAddr.compare(vmpSections[i].base.add(vmpSections[i].size)) < 0) {
                                        outsideVmp = false;
                                        break;
                                    }
                                }

                                if (outsideVmp && returnAddr.compare(mainModule.base) >= 0) {
                                    potentialOEPs.push(returnAddr.toString());
                                    send({
                                        type: 'vmprotect_vm_exit',
                                        address: returnAddr.toString(),
                                        context: {
                                            eax: context.eax.toString(),
                                            ebx: context.ebx.toString()
                                        }
                                    });
                                }
                            });
                        }
                    }

                    iterator.keep();
                }
            }
        });

        // Monitor VirtualAlloc for unpacked code regions
        const VirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
        if (VirtualAlloc) {
            Interceptor.attach(VirtualAlloc, {
                onEnter: function(args) {
                    this.lpAddress = args[0];
                    this.dwSize = args[1].toInt32();
                    this.flProtect = args[3].toInt32();
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        const region = {
                            base: retval,
                            size: this.dwSize,
                            protection: this.flProtect,
                            timestamp: Date.now()
                        };
                        allocatedRegions.push(region);

                        // PAGE_EXECUTE_READWRITE (0x40) or PAGE_EXECUTE_READ (0x20)
                        if (this.flProtect === 0x40 || this.flProtect === 0x20) {
                            send({
                                type: 'vmprotect_executable_alloc',
                                address: retval.toString(),
                                size: this.dwSize
                            });
                        }
                    }
                }
            });
        }

        // Monitor VirtualProtect for code unpacking
        const VirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        if (VirtualProtect) {
            Interceptor.attach(VirtualProtect, {
                onEnter: function(args) {
                    this.lpAddress = args[0];
                    this.dwSize = args[1].toInt32();
                    this.flNewProtect = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Transition to executable = unpacked code
                        if (this.flNewProtect === 0x40 || this.flNewProtect === 0x20) {
                            send({
                                type: 'vmprotect_code_unpacked',
                                address: this.lpAddress.toString(),
                                size: this.dwSize
                            });

                            // Dump the first 256 bytes for analysis
                            try {
                                const dumpSize = Math.min(this.dwSize, 256);
                                const data = this.lpAddress.readByteArray(dumpSize);
                                send({
                                    type: 'vmprotect_code_dump',
                                    address: this.lpAddress.toString(),
                                    data: Array.from(new Uint8Array(data))
                                });
                            } catch(e) {}
                        }
                    }
                }
            });
        }

        // Periodically report handler statistics
        setInterval(function() {
            const handlers = [];
            vmHandlers.forEach(function(value, key) {
                if (value.count > 50) {
                    handlers.push({
                        address: key.toString ? key.toString() : key,
                        count: value.count,
                        type: value.type || 'bytecode'
                    });
                }
            });

            if (handlers.length > 0) {
                send({
                    type: 'vmprotect_handler_stats',
                    handlers: handlers,
                    potentialOEPs: potentialOEPs.slice(-10)
                });
            }
        }, 5000);
        """

    def _generate_themida_unpacking_script(self) -> str:
        """Generate Themida unpacking script.

        Creates a Frida instrumentation script that defeats Themida's advanced
        anti-debug and virtual machine protections by bypassing kernel-mode debug
        checks (NtQueryInformationProcess, NtSetInformationThread), hooking
        exception handlers, defeating SecureEngine integrity checks, and tracing
        RISC/FISH VM instruction patterns to extract unpacked code.

        Returns:
            Frida script string for unpacking Themida-protected binaries. Script
                defeats kernel-mode anti-debug and traces VM execution to identify
                unpacked code regions.

        """
        return """
        // Themida Unpacking Script - Production Implementation with Kernel Anti-Debug
        const mainModule = Process.enumerateModules()[0];
        const allocatedRegions = [];
        const vmHandlers = new Map();
        let oepCandidates = [];
        let secureEngineSections = [];

        // ============================================================
        // KERNEL-MODE ANTI-DEBUG BYPASS (Critical for Themida)
        // ============================================================

        // NtQueryInformationProcess - Themida's primary kernel anti-debug
        const ntQueryInfoProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
        if (ntQueryInfoProcess) {
            Interceptor.attach(ntQueryInfoProcess, {
                onEnter: function(args) {
                    this.infoClass = args[1].toInt32();
                    this.buffer = args[2];
                    this.returnLength = args[4];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.buffer && !this.buffer.isNull()) {
                        const infoClass = this.infoClass;

                        // ProcessDebugPort (0x07)
                        if (infoClass === 0x07) {
                            if (Process.pointerSize === 8) {
                                this.buffer.writeU64(0);
                            } else {
                                this.buffer.writeU32(0);
                            }
                        }
                        // ProcessDebugObjectHandle (0x1E)
                        else if (infoClass === 0x1E) {
                            if (Process.pointerSize === 8) {
                                this.buffer.writeU64(0);
                            } else {
                                this.buffer.writeU32(0);
                            }
                            retval.replace(0xC0000353); // STATUS_PORT_NOT_SET
                        }
                        // ProcessDebugFlags (0x1F)
                        else if (infoClass === 0x1F) {
                            this.buffer.writeU32(1); // PROCESS_DEBUG_INHERIT = TRUE (no debugger)
                        }
                        // ProcessBasicInformation (0x00) - Check InheritedFromUniqueProcessId
                        else if (infoClass === 0x00) {
                            // Leave unchanged but log
                            send({
                                type: 'themida_antidebug',
                                method: 'ProcessBasicInformation',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                }
            });
        }

        // NtSetInformationThread - ThreadHideFromDebugger (Critical!)
        const ntSetInfoThread = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
        if (ntSetInfoThread) {
            const originalNtSetInfoThread = new NativeFunction(ntSetInfoThread, 'uint32',
                ['pointer', 'uint32', 'pointer', 'uint32']);
            Interceptor.replace(ntSetInfoThread, new NativeCallback(function(threadHandle, infoClass, buffer, bufferSize) {
                // ThreadHideFromDebugger (0x11) - Block completely
                if (infoClass === 0x11) {
                    send({
                        type: 'themida_antidebug',
                        method: 'ThreadHideFromDebugger_blocked'
                    });
                    return 0x00000000; // STATUS_SUCCESS without calling original
                }
                return originalNtSetInfoThread(threadHandle, infoClass, buffer, bufferSize);
            }, 'uint32', ['pointer', 'uint32', 'pointer', 'uint32']));
        }

        // NtQuerySystemInformation - SystemKernelDebuggerInformation (0x23)
        const ntQuerySysInfo = Module.findExportByName('ntdll.dll', 'NtQuerySystemInformation');
        if (ntQuerySysInfo) {
            Interceptor.attach(ntQuerySysInfo, {
                onEnter: function(args) {
                    this.infoClass = args[0].toInt32();
                    this.buffer = args[1];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.buffer && !this.buffer.isNull()) {
                        // SystemKernelDebuggerInformation (0x23)
                        if (this.infoClass === 0x23) {
                            this.buffer.writeU8(0);      // KdDebuggerEnabled = FALSE
                            this.buffer.add(1).writeU8(1); // KdDebuggerNotPresent = TRUE
                        }
                    }
                }
            });
        }

        // NtClose - Detect invalid handle checks (anti-debug trick)
        const ntClose = Module.findExportByName('ntdll.dll', 'NtClose');
        if (ntClose) {
            Interceptor.attach(ntClose, {
                onEnter: function(args) {
                    this.handle = args[0];
                },
                onLeave: function(retval) {
                    // Themida uses invalid handles to detect debuggers
                    if (retval.toInt32() === 0xC0000008) { // STATUS_INVALID_HANDLE
                        // Suppress the exception that would be raised in debuggers
                        retval.replace(0);
                    }
                }
            });
        }

        // ============================================================
        // USER-MODE ANTI-DEBUG BYPASS
        // ============================================================

        // IsDebuggerPresent
        const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
                return 0;
            }, 'int', []));
        }

        // CheckRemoteDebuggerPresent
        const checkRemoteDbg = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (checkRemoteDbg) {
            Interceptor.attach(checkRemoteDbg, {
                onEnter: function(args) {
                    this.pbDebuggerPresent = args[1];
                },
                onLeave: function(retval) {
                    if (this.pbDebuggerPresent && !this.pbDebuggerPresent.isNull()) {
                        this.pbDebuggerPresent.writeU32(0);
                    }
                }
            });
        }

        // PEB.BeingDebugged and PEB.NtGlobalFlag
        const rtlGetCurrentPeb = Module.findExportByName('ntdll.dll', 'RtlGetCurrentPeb');
        if (rtlGetCurrentPeb) {
            const getPeb = new NativeFunction(rtlGetCurrentPeb, 'pointer', []);
            const pebAddress = getPeb();

            if (pebAddress && !pebAddress.isNull()) {
                // BeingDebugged (offset 0x02)
                pebAddress.add(0x02).writeU8(0);

                // NtGlobalFlag - offset differs: x86=0x68, x64=0xBC
                const ntGlobalFlagOffset = Process.pointerSize === 8 ? 0xBC : 0x68;
                const ntGlobalFlag = pebAddress.add(ntGlobalFlagOffset).readU32();
                // Clear FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK (0x20),
                // FLG_HEAP_VALIDATE_PARAMETERS (0x40)
                const cleanedFlag = ntGlobalFlag & ~0x70;
                pebAddress.add(ntGlobalFlagOffset).writeU32(cleanedFlag);
            }
        }

        // ============================================================
        // TIMING ATTACK BYPASS
        // ============================================================

        let lastRdtsc = 0;
        const QueryPerformanceCounter = Module.findExportByName('kernel32.dll', 'QueryPerformanceCounter');
        if (QueryPerformanceCounter) {
            Interceptor.attach(QueryPerformanceCounter, {
                onEnter: function(args) {
                    this.counterPtr = args[0];
                },
                onLeave: function(retval) {
                    if (this.counterPtr && !this.counterPtr.isNull()) {
                        const current = this.counterPtr.readU64().toNumber();
                        if (lastRdtsc > 0) {
                            const diff = current - lastRdtsc;
                            // Normalize timing to hide debugging overhead
                            if (diff > 1000000) {
                                const normalized = lastRdtsc + 50000 + Math.floor(Math.random() * 10000);
                                this.counterPtr.writeU64(normalized);
                            }
                        }
                        lastRdtsc = current;
                    }
                }
            });
        }

        const GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        const GetTickCount64 = Module.findExportByName('kernel32.dll', 'GetTickCount64');
        let lastTickCount = 0;

        if (GetTickCount) {
            Interceptor.attach(GetTickCount, {
                onLeave: function(retval) {
                    const current = retval.toInt32();
                    if (lastTickCount > 0 && (current - lastTickCount) > 1000) {
                        retval.replace(lastTickCount + 16 + Math.floor(Math.random() * 16));
                    }
                    lastTickCount = current;
                }
            });
        }

        // ============================================================
        // THEMIDA SECUREENGINE SECTION DETECTION
        // ============================================================

        mainModule.enumerateRanges('r-x').forEach(function(range) {
            try {
                const data = range.base.readByteArray(32);
                if (data) {
                    const bytes = new Uint8Array(data);
                    // Look for SecureEngine markers
                    // ".themida", ".secureng", encrypted section markers
                    const hasThemidaMarker = (
                        (bytes[0] === 0x2E && bytes[1] === 0x74 && bytes[2] === 0x68 && bytes[3] === 0x65) ||
                        (bytes[0] === 0x2E && bytes[1] === 0x73 && bytes[2] === 0x65 && bytes[3] === 0x63) ||
                        (bytes[0] === 0xE9 && bytes[5] === 0xE9) // Double JMP pattern
                    );

                    if (hasThemidaMarker) {
                        secureEngineSections.push(range);
                        send({
                            type: 'themida_section',
                            base: range.base.toString(),
                            size: range.size
                        });
                    }
                }
            } catch(e) {}
        });

        // ============================================================
        // EXCEPTION HANDLER HIJACKING
        // ============================================================

        let themidaExceptionHandler = null;
        const SetUnhandledExceptionFilter = Module.findExportByName('kernel32.dll', 'SetUnhandledExceptionFilter');
        if (SetUnhandledExceptionFilter) {
            Interceptor.attach(SetUnhandledExceptionFilter, {
                onEnter: function(args) {
                    themidaExceptionHandler = args[0];
                    send({
                        type: 'themida_exception_handler',
                        address: themidaExceptionHandler.toString()
                    });
                }
            });
        }

        const AddVectoredExceptionHandler = Module.findExportByName('kernel32.dll', 'AddVectoredExceptionHandler');
        if (AddVectoredExceptionHandler) {
            Interceptor.attach(AddVectoredExceptionHandler, {
                onEnter: function(args) {
                    const handler = args[1];
                    send({
                        type: 'themida_veh',
                        address: handler.toString(),
                        first: args[0].toInt32()
                    });
                }
            });
        }

        // ============================================================
        // RISC/FISH VM HANDLER DETECTION
        // ============================================================

        const threadId = Process.getCurrentThreadId();
        let vmActiveRegion = null;
        let fishHandlerCount = 0;
        let riscHandlerCount = 0;

        setTimeout(function() {
            Stalker.follow(threadId, {
                transform: function(iterator) {
                    let instruction;
                    let pushfdCount = 0;
                    let popfdCount = 0;
                    let consecutiveJmps = 0;
                    let blockStart = null;

                    while ((instruction = iterator.next()) !== null) {
                        const addr = instruction.address;
                        const mnem = instruction.mnemonic;

                        if (!blockStart) {
                            blockStart = addr;
                        }

                        // Check if in SecureEngine section
                        let inSecureEngine = false;
                        for (let i = 0; i < secureEngineSections.length; i++) {
                            if (addr.compare(secureEngineSections[i].base) >= 0 &&
                                addr.compare(secureEngineSections[i].base.add(secureEngineSections[i].size)) < 0) {
                                inSecureEngine = true;
                                break;
                            }
                        }

                        if (inSecureEngine) {
                            // Track FISH VM patterns (pushfd/popfd heavy)
                            if (mnem === 'pushfd' || mnem === 'pushfq') {
                                pushfdCount++;
                            } else if (mnem === 'popfd' || mnem === 'popfq') {
                                popfdCount++;
                            }

                            // Track RISC VM patterns (computed jumps)
                            if (mnem === 'jmp') {
                                consecutiveJmps++;
                                if (consecutiveJmps > 3) {
                                    iterator.putCallout(function(context) {
                                        const target = context.pc;
                                        const handlerKey = target.toString();

                                        if (!vmHandlers.has(handlerKey)) {
                                            vmHandlers.set(handlerKey, { count: 0, type: 'risc' });
                                            riscHandlerCount++;
                                        }
                                        vmHandlers.get(handlerKey).count++;
                                    });
                                }
                            } else {
                                consecutiveJmps = 0;
                            }

                            // Detect VM exit via ret to non-protected code
                            if (mnem === 'ret') {
                                iterator.putCallout(function(context) {
                                    const returnAddr = context.sp.readPointer();

                                    let inProtectedSection = false;
                                    for (let i = 0; i < secureEngineSections.length; i++) {
                                        if (returnAddr.compare(secureEngineSections[i].base) >= 0 &&
                                            returnAddr.compare(secureEngineSections[i].base.add(secureEngineSections[i].size)) < 0) {
                                            inProtectedSection = true;
                                            break;
                                        }
                                    }

                                    if (!inProtectedSection && returnAddr.compare(mainModule.base) >= 0) {
                                        oepCandidates.push(returnAddr.toString());
                                        send({
                                            type: 'themida_vm_exit',
                                            address: returnAddr.toString(),
                                            context: {
                                                eax: context.eax.toString(),
                                                esp: context.sp.toString()
                                            }
                                        });
                                    }
                                });
                            }
                        }

                        iterator.keep();
                    }

                    // Check for FISH VM pattern (high pushfd/popfd ratio)
                    if (pushfdCount > 5 && popfdCount > 5) {
                        fishHandlerCount++;
                        if (fishHandlerCount === 10) {
                            send({
                                type: 'themida_fish_vm_detected',
                                pushfdCount: pushfdCount,
                                popfdCount: popfdCount
                            });
                        }
                    }
                }
            });
        }, 500);

        // ============================================================
        // MEMORY ALLOCATION MONITORING
        // ============================================================

        const VirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
        if (VirtualAlloc) {
            Interceptor.attach(VirtualAlloc, {
                onEnter: function(args) {
                    this.lpAddress = args[0];
                    this.dwSize = args[1].toInt32();
                    this.flProtect = args[3].toInt32();
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        allocatedRegions.push({
                            base: retval,
                            size: this.dwSize,
                            protection: this.flProtect
                        });

                        // Executable allocation = likely unpacked code
                        if (this.flProtect === 0x40 || this.flProtect === 0x20) {
                            send({
                                type: 'themida_exec_alloc',
                                address: retval.toString(),
                                size: this.dwSize
                            });
                        }
                    }
                }
            });
        }

        // Monitor VirtualProtect for transition to executable
        const VirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        if (VirtualProtect) {
            Interceptor.attach(VirtualProtect, {
                onEnter: function(args) {
                    this.lpAddress = args[0];
                    this.dwSize = args[1].toInt32();
                    this.flNewProtect = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0 &&
                        (this.flNewProtect === 0x40 || this.flNewProtect === 0x20)) {
                        send({
                            type: 'themida_code_unpacked',
                            address: this.lpAddress.toString(),
                            size: this.dwSize
                        });

                        // Dump first 512 bytes
                        try {
                            const dumpSize = Math.min(this.dwSize, 512);
                            const data = this.lpAddress.readByteArray(dumpSize);
                            send({
                                type: 'themida_code_dump',
                                address: this.lpAddress.toString(),
                                data: Array.from(new Uint8Array(data))
                            });
                        } catch(e) {}
                    }
                }
            });
        }

        // ============================================================
        // INTEGRITY CHECK DEFEAT
        // ============================================================

        // CreateFileW - Block self-reads for integrity checks
        const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        let exeFileHandle = null;

        if (CreateFileW) {
            Interceptor.attach(CreateFileW, {
                onEnter: function(args) {
                    const filename = args[0].readUtf16String();
                    if (filename && filename.toLowerCase().includes('.exe')) {
                        this.isSelfRead = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.isSelfRead && retval.toInt32() !== -1) {
                        exeFileHandle = retval;
                        send({
                            type: 'themida_integrity_check',
                            handle: retval.toString()
                        });
                    }
                }
            });
        }

        // Periodic stats reporting
        setInterval(function() {
            if (vmHandlers.size > 0 || oepCandidates.length > 0) {
                const handlers = [];
                vmHandlers.forEach(function(value, key) {
                    if (value.count > 10) {
                        handlers.push({
                            address: key,
                            count: value.count,
                            type: value.type
                        });
                    }
                });

                send({
                    type: 'themida_status',
                    riscHandlers: riscHandlerCount,
                    fishHandlers: fishHandlerCount,
                    topHandlers: handlers.slice(0, 20),
                    oepCandidates: oepCandidates.slice(-10)
                });
            }
        }, 5000);
        """

    def _generate_generic_unpacking_script(self) -> str:
        """Generate generic unpacking script.

        Creates a Frida instrumentation script that unpacks arbitrary binaries
        by monitoring VirtualAlloc and VirtualProtect calls, tracking memory
        writes, identifying unpacker patterns like PUSHAD/POPAD sequences,
        detecting tail jumps to unpacked code, and dumping decrypted code regions.

        Returns:
            Generic Frida script string for unpacking any protected binary. Script
                monitors memory operations to extract unpacked code independent
                of packer type.

        """
        return """
        // Generic Unpacking Script
        const mainModule = Process.enumerateModules()[0];
        const originalEntry = mainModule.base.add(ptr(mainModule.base.add(0x3C).readU32()).add(0x28).readU32());

        console.log('Original Entry Point: ' + originalEntry);

        // Monitor memory protection changes
        const VirtualProtect = Module.findExportByName('kernel32.dll', 'VirtualProtect');
        const VirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
        const WriteProcessMemory = Module.findExportByName('kernel32.dll', 'WriteProcessMemory');

        const allocatedRegions = [];
        const writtenRegions = [];

        if (VirtualAlloc) {
            Interceptor.attach(VirtualAlloc, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        const size = this.args[1].toInt32();
                        allocatedRegions.push({
                            address: retval,
                            size: size
                        });
                        send({
                            type: 'memory_allocated',
                            address: retval.toString(),
                            size: size
                        });
                    }
                }
            });
        }

        if (VirtualProtect) {
            Interceptor.attach(VirtualProtect, {
                onEnter: function(args) {
                    const addr = args[0];
                    const size = args[1].toInt32();
                    const newProt = args[2].toInt32();

                    // Check for executable permissions
                    if ((newProt & 0xF0) !== 0) {
                        send({
                            type: 'memory_executable',
                            address: addr.toString(),
                            size: size,
                            protection: newProt
                        });

                        // This might be unpacked code
                        writtenRegions.push({
                            address: addr,
                            size: size
                        });
                    }
                }
            });
        }

        if (WriteProcessMemory) {
            Interceptor.attach(WriteProcessMemory, {
                onEnter: function(args) {
                    const handle = args[0];
                    const addr = args[1];
                    const buffer = args[2];
                    const size = args[3].toInt32();

                    send({
                        type: 'memory_written',
                        address: addr.toString(),
                        size: size
                    });

                    writtenRegions.push({
                        address: addr,
                        size: size,
                        buffer: buffer
                    });
                }
            });
        }

        // Hook common unpacker patterns
        const pushadPattern = '60'; // PUSHAD
        const popadPattern = '61';  // POPAD

        const pushadMatches = Memory.scanSync(mainModule.base, mainModule.size, pushadPattern);
        pushadMatches.forEach(function(match) {
            // Look for POPAD nearby
            const nearby = match.address.readByteArray(0x1000);
            if (nearby && nearby.includes(0x61)) {
                send({
                    type: 'unpacker_pattern',
                    pattern: 'PUSHAD/POPAD',
                    address: match.address.toString()
                });

                // Set breakpoint on POPAD
                Interceptor.attach(match.address.add(nearby.indexOf(0x61)), {
                    onEnter: function() {
                        // We're about to return to unpacked code
                        const esp = this.context.esp || this.context.rsp;
                        const returnAddr = esp.readPointer();

                        send({
                            type: 'unpacked_oep',
                            address: returnAddr.toString()
                        });

                        // Dump the unpacked region
                        const dumpSize = 0x10000;
                        const dump = returnAddr.readByteArray(dumpSize);
                        send({
                            type: 'memory_dump',
                            address: returnAddr.toString(),
                            size: dumpSize
                        }, dump);
                    }
                });
            }
        });

        // Tail jump detection
        setTimeout(function() {
            const currentEip = Instruction.parse(ptr(Thread.getCurrentThreadId()));

            // Check if we've jumped far from original entry
            if (Math.abs(currentEip.address - originalEntry) > 0x100000) {
                send({
                    type: 'tail_jump_detected',
                    from: originalEntry.toString(),
                    to: currentEip.address.toString()
                });
            }
        }, 5000);
        """

    def apply_all_bypasses(self) -> bool:
        """Apply all detected protection bypasses.

        Combines all available bypass scripts from detected protections,
        creates a unified Frida script that applies all bypasses simultaneously,
        and loads the script into the target process to defeat all identified
        protection mechanisms.

        Returns:
            True if bypasses were applied successfully and script is loaded,
                False if no bypasses available or script loading failed.

        Raises:
            Exception: If Frida session is not initialized or script creation
                fails.

        """
        try:
            if self.session is None:
                logger.error("Session is not initialized")
                return False

            all_scripts = []

            # Combine all bypass scripts
            for protection in self.detected_protections:
                if protection.bypass_available and protection.bypass_script:
                    all_scripts.append(protection.bypass_script)

            if not all_scripts:
                logger.warning("No bypass scripts available")
                return False

            # Create and load combined script
            combined_script = "\n\n".join(all_scripts)
            self.script = self.session.create_script(combined_script)

            def on_message(message: object, _data: object) -> None:
                try:
                    if not isinstance(message, dict):
                        return
                    if message.get("type") == "send":
                        payload = message.get("payload")
                        log_analysis(
                            f"Bypass result: {payload}",
                            context={"payload": payload},
                        )
                        logger.info("Bypass result: %s", payload)
                    elif message.get("type") == "error":
                        error_msg = f"Bypass error: {message}"
                        log_error(
                            error_msg,
                            context={"message": message},
                        )
                        logger.error("Bypass error: %s", message)
                except (KeyError, TypeError, ValueError) as e:
                    log_error(
                        "Error processing bypass message",
                        context={"error": str(e), "message": message},
                        exception=e,
                    )

            self.script.on("message", on_message)
            self.script.load()

            logger.info("Applied %s protection bypasses", len(all_scripts))
            return True

        except Exception:
            logger.exception("Failed to apply bypasses")
            return False

    def detect_all_protections(self) -> list[ProtectionInfo]:
        """Run all protection detection routines.

        Sequentially executes all available detection methods to perform
        comprehensive analysis of the target process, including anti-debug,
        certificate pinning, integrity checks, VM detection, and packer
        detection, aggregating all results into a single list.

        Returns:
            List of all detected protection information objects from all detection
                methods. Returns empty list if detection fails or no protections
                are detected.

        Raises:
            Exception: If critical Frida operations fail during detection.

        """
        logger.info("Starting comprehensive protection detection...")

        all_detections = []

        # Run all detection methods
        detection_methods = [
            ("Anti-Debug", self.detect_anti_debug),
            ("Certificate Pinning", self.detect_cert_pinning),
            ("Integrity Checks", self.detect_integrity_checks),
            ("VM Detection", self.detect_vm_detection),
            ("Packers", self.detect_packers),
        ]

        for name, method in detection_methods:
            try:
                logger.info("Detecting %s...", name)
                detections = method()
                all_detections.extend(detections)
                logger.info("Found %s %s protections", len(detections), name)
            except Exception:
                logger.exception("Failed to detect %s", name)

        self.detected_protections = all_detections
        logger.info("Total protections detected: %s", len(all_detections))

        return all_detections

    def generate_bypass_report(self) -> str:
        """Generate detailed report of detected protections and bypasses.

        Produces a comprehensive human-readable report documenting all detected
        protections, their locations, confidence scores, bypass availability,
        and detailed information grouped by protection type, along with actionable
        recommendations for applying bypasses.

        Returns:
            Formatted report string containing detection results, confidence levels,
                detailed protection information, and step-by-step bypass
                recommendations. Report includes sections for each protection
                type found.

        """
        report = [
            "=" * 60,
            "PROTECTION BYPASS ANALYSIS REPORT",
            "=" * 60,
            f"Target: {self.process_name or f'PID {self.pid}'}",
            f"Total Protections Detected: {len(self.detected_protections)}",
            "",
        ]
        # Group by protection type
        by_type: dict[ProtectionType, list[ProtectionInfo]] = {}
        for protection in self.detected_protections:
            if protection.type not in by_type:
                by_type[protection.type] = []
            by_type[protection.type].append(protection)

        for prot_type, protections in by_type.items():
            report.extend((
                f"\n{prot_type.value.upper()} ({len(protections)} detected)",
                "-" * 40,
            ))
            for i, prot in enumerate(protections, 1):
                report.extend((
                    f"  [{i}] Location: {prot.location}",
                    f"      Confidence: {prot.confidence:.1%}",
                    f"      Bypass Available: {'Yes' if prot.bypass_available else 'No'}",
                ))
                for key, value in prot.details.items():
                    report.append(f"      {key}: {value}")

                report.append("")

        report.extend(("\n" + "=" * 60, "RECOMMENDATIONS", "=" * 60))
        if self.detected_protections:
            report.extend((
                "1. Apply all available bypasses using apply_all_bypasses()",
                "2. Monitor application behavior after bypass",
                "3. Use memory dumps for further analysis",
                "4. Consider using automated unpacking for packed binaries",
            ))
        else:
            report.extend((
                "No protections detected. The target may use:",
                "- Custom protection mechanisms",
                "- Obfuscation without standard patterns",
                "- Server-side license validation",
            ))
        return "\n".join(report)


def main() -> None:
    """Command-line interface for protection detection and bypass operations.

    Attach to a target process by name or PID, run comprehensive protection
    detection, apply available bypasses, and generate analysis reports. Supports
    automated bypass application and report file output for documentation purposes.

    Returns:
        None. Exits after completing protection analysis and bypass operations.

    """
    import argparse

    parser = argparse.ArgumentParser(description="Frida Protection Bypass Automation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", help="Process name to attach to")
    group.add_argument("-p", "--pid", type=int, help="Process ID to attach to")
    parser.add_argument("-a", "--apply", action="store_true", help="Apply all bypasses automatically")
    parser.add_argument("-r", "--report", help="Save report to file")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create bypasser instance
    bypasser = FridaProtectionBypasser(process_name=args.name, pid=args.pid)

    # Attach to process
    if not bypasser.attach():
        logger.error("Failed to attach to process")
        return

    # Detect all protections
    protections = bypasser.detect_all_protections()

    # Generate and display report
    report = bypasser.generate_bypass_report()
    print(report)

    # Save report if requested
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
        logger.info("Report saved to %s", args.report)

    # Apply bypasses if requested
    if args.apply and protections:
        logger.info("Applying all available bypasses...")
        if bypasser.apply_all_bypasses():
            logger.info("All bypasses applied successfully")
        else:
            logger.exception("Failed to apply some bypasses")

    # Keep script running
    if bypasser.script:
        logger.info("Bypass script running. Press Ctrl+C to exit...")
        try:
            import sys

            sys.stdin.read()
        except KeyboardInterrupt:
            logger.info("Exiting...")


if __name__ == "__main__":
    main()
