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
        """Attach to target process."""
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
        except Exception as e:
            logger.exception("Failed to attach: %s", e, exc_info=True)
            return False

    def detect_anti_debug(self) -> list[ProtectionInfo]:
        """Detect anti-debugging mechanisms."""
        detections = []

        anti_debug_script = """
        const detections = [];

        // Windows anti-debug detection
        if (Process.platform === 'windows') {
            // IsDebuggerPresent detection
            const isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
            if (isDebuggerPresent) {
                Interceptor.attach(isDebuggerPresent, {
                    onEnter: function(args) {
                        send({
                            type: 'anti_debug',
                            method: 'IsDebuggerPresent',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                    }
                });
                detections.push('IsDebuggerPresent');
            }

            // CheckRemoteDebuggerPresent detection
            const checkRemoteDebugger = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
            if (checkRemoteDebugger) {
                Interceptor.attach(checkRemoteDebugger, {
                    onEnter: function(args) {
                        this.pbDebuggerPresent = args[1];
                        send({
                            type: 'anti_debug',
                            method: 'CheckRemoteDebuggerPresent',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        if (this.pbDebuggerPresent) {
                            this.pbDebuggerPresent.writeU8(0);
                        }
                        retval.replace(1);
                    }
                });
                detections.push('CheckRemoteDebuggerPresent');
            }

            // NtQueryInformationProcess detection
            const ntdll = Process.getModuleByName('ntdll.dll');
            const ntQueryInfoProcess = Module.findExportByName('ntdll.dll', 'NtQueryInformationProcess');
            if (ntQueryInfoProcess) {
                Interceptor.attach(ntQueryInfoProcess, {
                    onEnter: function(args) {
                        this.infoClass = args[1].toInt32();
                        this.buffer = args[2];
                        send({
                            type: 'anti_debug',
                            method: 'NtQueryInformationProcess',
                            infoClass: this.infoClass,
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        // ProcessDebugPort (0x07)
                        if (this.infoClass === 0x07 && this.buffer) {
                            this.buffer.writePointer(ptr(0));
                        }
                        // ProcessDebugObjectHandle (0x1E)
                        else if (this.infoClass === 0x1E && this.buffer) {
                            this.buffer.writePointer(ptr(0));
                        }
                        // ProcessDebugFlags (0x1F)
                        else if (this.infoClass === 0x1F && this.buffer) {
                            this.buffer.writeU32(1);
                        }
                    }
                });
                detections.push('NtQueryInformationProcess');
            }

            // PEB BeingDebugged flag
            const peb = Process.enumerateModules()[0].base;
            const beingDebuggedOffset = Process.pointerSize === 8 ? 0x02 : 0x02;
            const beingDebuggedPtr = peb.add(beingDebuggedOffset);

            // Monitor PEB access
            Memory.protect(beingDebuggedPtr, 1, 'r--');
            Process.setExceptionHandler(function(details) {
                if (details.address.equals(beingDebuggedPtr)) {
                    send({
                        type: 'anti_debug',
                        method: 'PEB.BeingDebugged',
                        location: details.context.pc.toString()
                    });
                    // Clear the flag
                    beingDebuggedPtr.writeU8(0);
                    return true;
                }
                return false;
            });

            // Hardware breakpoint detection
            const getThreadContext = Module.findExportByName('kernel32.dll', 'GetThreadContext');
            if (getThreadContext) {
                Interceptor.attach(getThreadContext, {
                    onEnter: function(args) {
                        this.context = args[1];
                    },
                    onLeave: function(retval) {
                        if (this.context && retval.toInt32() !== 0) {
                            // Clear DR0-DR3 debug registers
                            const dr0Offset = Process.pointerSize === 8 ? 0x18 : 0x04;
                            for (let i = 0; i < 4; i++) {
                                this.context.add(dr0Offset + i * Process.pointerSize).writePointer(ptr(0));
                            }
                            send({
                                type: 'anti_debug',
                                method: 'Hardware Breakpoint Check',
                                location: this.returnAddress.toString()
                            });
                        }
                    }
                });
                detections.push('Hardware Breakpoints');
            }

        } else if (Process.platform === 'linux' || Process.platform === 'android') {
            // ptrace detection
            const ptrace = Module.findExportByName(null, 'ptrace');
            if (ptrace) {
                Interceptor.attach(ptrace, {
                    onEnter: function(args) {
                        const request = args[0].toInt32();
                        if (request === 0) { // PTRACE_TRACEME
                            send({
                                type: 'anti_debug',
                                method: 'ptrace(PTRACE_TRACEME)',
                                location: this.returnAddress.toString()
                            });
                            // Prevent ptrace
                            args[0] = ptr(-1);
                        }
                    }
                });
                detections.push('ptrace');
            }

            // /proc/self/status TracerPid check
            const fopen = Module.findExportByName(null, 'fopen');
            if (fopen) {
                Interceptor.attach(fopen, {
                    onEnter: function(args) {
                        const path = args[0].readCString();
                        if (path && path.includes('/proc/self/status')) {
                            this.isStatusFile = true;
                            send({
                                type: 'anti_debug',
                                method: '/proc/self/status check',
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        if (this.isStatusFile && !retval.isNull()) {
                            // Hook fgets to modify TracerPid
                            const fgets = Module.findExportByName(null, 'fgets');
                            if (fgets) {
                                Interceptor.attach(fgets, {
                                    onLeave: function(retval) {
                                        if (!retval.isNull()) {
                                            const line = retval.readCString();
                                            if (line && line.includes('TracerPid:')) {
                                                retval.writeUtf8String('TracerPid:\\t0\\n');
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    }
                });
                detections.push('/proc/self/status');
            }
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, data: object) -> None:
            if message["type"] == "send":
                payload = message["payload"]
                if payload["type"] == "anti_debug":
                    info = ProtectionInfo(
                        type=ProtectionType.ANTI_DEBUG,
                        location=payload["location"],
                        confidence=0.95,
                        details={"method": payload.get("method", "Unknown")},
                        bypass_available=True,
                        bypass_script=anti_debug_script,
                    )
                    detections.append(info)

        try:
            script = self.session.create_script(anti_debug_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)  # Wait for detections
            script.unload()
        except Exception as e:
            logger.exception("Anti-debug detection failed: %s", e, exc_info=True)

        return detections

    def detect_cert_pinning(self) -> list[ProtectionInfo]:
        """Detect certificate pinning implementations."""
        detections = []

        cert_pinning_script = """
        const detections = [];

        // Android certificate pinning detection
        if (Process.platform === 'android') {
            // OkHttp3 CertificatePinner
            try {
                const CertificatePinner = Java.use('okhttp3.CertificatePinner');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
                    send({
                        type: 'cert_pinning',
                        method: 'OkHttp3.CertificatePinner',
                        hostname: hostname,
                        location: 'okhttp3.CertificatePinner.check'
                    });
                    return; // Bypass
                };
                detections.push('OkHttp3');
            } catch(e) {}

            // TrustManagerImpl
            try {
                const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    send({
                        type: 'cert_pinning',
                        method: 'TrustManagerImpl',
                        hostname: host,
                        location: 'TrustManagerImpl.verifyChain'
                    });
                    return untrustedChain;
                };
                detections.push('TrustManagerImpl');
            } catch(e) {}

            // Network Security Config
            try {
                const NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
                NetworkSecurityTrustManager.checkPins.implementation = function(pins) {
                    send({
                        type: 'cert_pinning',
                        method: 'NetworkSecurityConfig',
                        location: 'NetworkSecurityTrustManager.checkPins'
                    });
                    return;
                };
                detections.push('NetworkSecurityConfig');
            } catch(e) {}

        } else if (Process.platform === 'ios') {
            // iOS SSL pinning detection
            const SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
            const SSLCreateContext = Module.findExportByName('Security', 'SSLCreateContext');
            const SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
            const tls_helper_create_peer_trust = Module.findExportByName('libboringssl.dylib', 'tls_helper_create_peer_trust');

            if (SSLSetSessionOption) {
                Interceptor.attach(SSLSetSessionOption, {
                    onEnter: function(args) {
                        const option = args[1].toInt32();
                        if (option === 4) { // kSSLSessionOptionBreakOnServerAuth
                            send({
                                type: 'cert_pinning',
                                method: 'SSLSetSessionOption',
                                location: this.returnAddress.toString()
                            });
                            args[2] = ptr(0); // Disable cert validation
                        }
                    }
                });
                detections.push('SSLSetSessionOption');
            }

            if (tls_helper_create_peer_trust) {
                Interceptor.attach(tls_helper_create_peer_trust, {
                    onLeave: function(retval) {
                        send({
                            type: 'cert_pinning',
                            method: 'tls_helper_create_peer_trust',
                            location: this.returnAddress.toString()
                        });
                        retval.replace(ptr(0)); // Return NULL to bypass
                    }
                });
                detections.push('tls_helper_create_peer_trust');
            }

        } else if (Process.platform === 'windows') {
            // Windows certificate validation
            const CertVerifyCertificateChainPolicy = Module.findExportByName('crypt32.dll', 'CertVerifyCertificateChainPolicy');
            if (CertVerifyCertificateChainPolicy) {
                Interceptor.attach(CertVerifyCertificateChainPolicy, {
                    onEnter: function(args) {
                        send({
                            type: 'cert_pinning',
                            method: 'CertVerifyCertificateChainPolicy',
                            location: this.returnAddress.toString()
                        });
                    },
                    onLeave: function(retval) {
                        retval.replace(1); // Return success
                    }
                });
                detections.push('CertVerifyCertificateChainPolicy');
            }

            // WinHTTP certificate validation
            const WinHttpSetOption = Module.findExportByName('winhttp.dll', 'WinHttpSetOption');
            if (WinHttpSetOption) {
                Interceptor.attach(WinHttpSetOption, {
                    onEnter: function(args) {
                        const option = args[1].toInt32();
                        if (option === 31) { // WINHTTP_OPTION_SECURITY_FLAGS
                            send({
                                type: 'cert_pinning',
                                method: 'WinHttpSetOption',
                                location: this.returnAddress.toString()
                            });
                            // Add flags to ignore cert errors
                            const flags = args[2].readU32();
                            args[2].writeU32(flags | 0x3300); // Ignore all cert errors
                        }
                    }
                });
                detections.push('WinHttpSetOption');
            }
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, data: object) -> None:
            if message["type"] == "send":
                payload = message["payload"]
                if payload["type"] == "cert_pinning":
                    info = ProtectionInfo(
                        type=ProtectionType.CERT_PINNING,
                        location=payload.get("location", "N/A"),
                        confidence=0.90,
                        details={
                            "method": payload.get("method", "Unknown"),
                            "hostname": payload.get("hostname", "N/A"),
                        },
                        bypass_available=True,
                        bypass_script=cert_pinning_script,
                    )
                    detections.append(info)

        try:
            script = self.session.create_script(cert_pinning_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception as e:
            logger.exception("Certificate pinning detection failed: %s", e, exc_info=True)

        return detections

    def detect_integrity_checks(self) -> list[ProtectionInfo]:
        """Detect integrity check mechanisms."""
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

        def on_message(message: object, data: object) -> None:
            if message["type"] == "send":
                payload = message["payload"]
                if payload["type"] == "integrity_check":
                    info = ProtectionInfo(
                        type=ProtectionType.INTEGRITY_CHECK,
                        location=payload.get("location", "N/A"),
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

        try:
            script = self.session.create_script(integrity_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception as e:
            logger.exception("Integrity check detection failed: %s", e, exc_info=True)

        return detections

    def detect_vm_detection(self) -> list[ProtectionInfo]:
        """Detect VM/sandbox detection mechanisms."""
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

            // CPUID instruction detection
            const cpuidAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, '0f a2');

            cpuidAddresses.forEach(function(match) {
                send({
                    type: 'vm_detection',
                    method: 'CPUID Instruction',
                    address: match.address.toString()
                });

                // Patch CPUID to return non-VM values
                Memory.protect(match.address, 2, 'rwx');
                match.address.writeByteArray([0x90, 0x90]); // NOP
            });

            if (cpuidAddresses.length > 0) {
                detections.push('CPUID');
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

            // Timing checks (RDTSC)
            const rdtscAddresses = Memory.scanSync(Process.enumerateModules()[0].base,
                Process.enumerateModules()[0].size, '0f 31');

            rdtscAddresses.forEach(function(match) {
                send({
                    type: 'vm_detection',
                    method: 'RDTSC Timing',
                    address: match.address.toString()
                });

                // Patch RDTSC to return consistent values
                Memory.protect(match.address, 2, 'rwx');
                match.address.writeByteArray([0x31, 0xc0]); // XOR EAX, EAX
            });

            if (rdtscAddresses.length > 0) {
                detections.push('RDTSC');
            }

        } else if (Process.platform === 'linux' || Process.platform === 'android') {
            // Check /proc/cpuinfo for VM signatures
            const fopen = Module.findExportByName(null, 'fopen');
            if (fopen) {
                Interceptor.attach(fopen, {
                    onEnter: function(args) {
                        const path = args[0].readCString();
                        if (path && path.includes('/proc/cpuinfo')) {
                            this.isCpuInfo = true;
                            send({
                                type: 'vm_detection',
                                method: '/proc/cpuinfo Check',
                                location: this.returnAddress.toString()
                            });
                        }
                    },
                    onLeave: function(retval) {
                        if (this.isCpuInfo && !retval.isNull()) {
                            // Hook reads to filter VM signatures
                            const fread = Module.findExportByName(null, 'fread');
                            if (fread) {
                                Interceptor.attach(fread, {
                                    onLeave: function(retval) {
                                        if (retval.toInt32() > 0) {
                                            const buffer = this.args[0];
                                            let content = buffer.readCString();
                                            if (content) {
                                                // Remove VM signatures
                                                content = content.replace(/QEMU|VirtualBox|VMware|KVM|Xen/gi, 'Intel');
                                                buffer.writeUtf8String(content);
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    }
                });
                detections.push('/proc/cpuinfo');
            }

            // DMI/SMBIOS checks
            const access = Module.findExportByName(null, 'access');
            if (access) {
                Interceptor.attach(access, {
                    onEnter: function(args) {
                        const path = args[0].readCString();
                        if (path && path.includes('/sys/class/dmi')) {
                            send({
                                type: 'vm_detection',
                                method: 'DMI/SMBIOS Check',
                                path: path,
                                location: this.returnAddress.toString()
                            });
                            // Make it fail
                            args[0] = Memory.allocUtf8String('/nonexistent');
                        }
                    }
                });
                detections.push('DMI/SMBIOS');
            }
        }

        send({
            type: 'detection_complete',
            detections: detections
        });
        """

        def on_message(message: object, data: object) -> None:
            if message["type"] == "send":
                payload = message["payload"]
                if payload["type"] == "vm_detection":
                    info = ProtectionInfo(
                        type=ProtectionType.VM_DETECTION,
                        location=payload.get("location", payload.get("address", "N/A")),
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

        try:
            script = self.session.create_script(vm_detection_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()
        except Exception as e:
            logger.exception("VM detection failed: %s", e, exc_info=True)

        return detections

    def detect_packers(self) -> list[ProtectionInfo]:
        """Detect known packers and protectors."""
        detections = []

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
            # Get the main module
            frida.get_local_device().enumerate_processes()[0]

            # Read first 4KB of main module for signatures
            module_base = self.session.get_module_by_name(self.process_name or "main").base_address

            header_data = self.session.read_bytes(module_base, 4096)

            for packer_name, signatures in packer_signatures.items():
                for signature in signatures:
                    if signature in header_data:
                        info = ProtectionInfo(
                            type=ProtectionType.PACKER,
                            location=f"Module header @ {hex(module_base)}",
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

            def on_message(message: object, data: object) -> None:
                if message["type"] == "send":
                    payload = message["payload"]
                    if payload["type"] == "packer_heuristic":
                        info = ProtectionInfo(
                            type=ProtectionType.PACKER,
                            location=payload.get("address", "N/A"),
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

            script = self.session.create_script(heuristic_script)
            script.on("message", on_message)
            script.load()
            time.sleep(2)
            script.unload()

        except Exception as e:
            logger.exception("Packer detection failed: %s", e, exc_info=True)

        return detections

    def _generate_unpacking_script(self, packer_name: str) -> str:
        """Generate packer-specific unpacking script."""
        if packer_name == "UPX":
            return self._generate_upx_unpacking_script()
        if packer_name == "VMProtect":
            return self._generate_vmprotect_unpacking_script()
        if packer_name == "Themida":
            return self._generate_themida_unpacking_script()
        return self._generate_generic_unpacking_script()

    def _generate_upx_unpacking_script(self) -> str:
        """Generate UPX unpacking script."""
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
        """Generate VMProtect unpacking script."""
        return """
        // VMProtect Unpacking Script
        const mainModule = Process.enumerateModules()[0];

        // VMProtect uses virtualization, we need to trace execution
        Stalker.follow({
            events: {
                call: true,
                ret: true,
                exec: true
            },
            onCallSummary: function(summary) {
                // Look for characteristic VMProtect patterns
                Object.keys(summary).forEach(function(target) {
                    const count = summary[target];
                    if (count > 1000) {
                        // High call frequency indicates VM handlers
                        send({
                            type: 'vmprotect_handler',
                            address: target,
                            count: count
                        });
                    }
                });
            },
            onReceive: function(events) {
                const opcodes = Stalker.parse(events);

                // Look for VM exit points
                opcodes.forEach(function(op) {
                    if (op.mnemonic === 'ret' && op.address > mainModule.base.add(0x1000)) {
                        // Potential OEP
                        send({
                            type: 'potential_oep',
                            address: op.address.toString()
                        });
                    }
                });
            }
        });

        // Hook memory allocation for unpacked code
        const VirtualAlloc = Module.findExportByName('kernel32.dll', 'VirtualAlloc');
        if (VirtualAlloc) {
            Interceptor.attach(VirtualAlloc, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        // Monitor writes to allocated memory
                        const size = this.args[1].toInt32();
                        Process.setExceptionHandler(function(details) {
                            if (details.type === 'access-violation' &&
                                details.address >= retval &&
                                details.address < retval.add(size)) {
                                send({
                                    type: 'vmprotect_write',
                                    address: details.address.toString()
                                });
                            }
                        });
                    }
                }
            });
        }
        """

    def _generate_themida_unpacking_script(self) -> str:
        """Generate Themida unpacking script."""
        return """
        // Themida Unpacking Script
        const mainModule = Process.enumerateModules()[0];

        // Themida uses advanced anti-debug and VM techniques
        // First, bypass anti-debug checks
        const IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        Interceptor.replace(IsDebuggerPresent, new NativeCallback(function() {
            return 0;
        }, 'int', []));

        // Hook Themida's exception handler setup
        const SetUnhandledExceptionFilter = Module.findExportByName('kernel32.dll', 'SetUnhandledExceptionFilter');
        let themidaHandler = null;

        Interceptor.attach(SetUnhandledExceptionFilter, {
            onEnter: function(args) {
                themidaHandler = args[0];
                send({
                    type: 'themida_handler',
                    address: themidaHandler.toString()
                });
            }
        });

        // Monitor for Themida's signature checks
        const CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        Interceptor.attach(CreateFileW, {
            onEnter: function(args) {
                const filename = args[0].readUtf16String();
                if (filename && filename.includes('.exe')) {
                    // Themida checking its own file
                    this.isExeFile = true;
                }
            },
            onLeave: function(retval) {
                if (this.isExeFile) {
                    // Hook subsequent reads
                    const ReadFile = Module.findExportByName('kernel32.dll', 'ReadFile');
                    Interceptor.attach(ReadFile, {
                        onEnter: function(args) {
                            this.buffer = args[1];
                            this.size = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            if (this.buffer && this.size > 0x1000) {
                                // Large read, possibly unpacked data
                                send({
                                    type: 'themida_unpacked',
                                    buffer: this.buffer.toString(),
                                    size: this.size
                                });
                            }
                        }
                    });
                }
            }
        });

        // Trace Themida VM
        setTimeout(function() {
            Stalker.follow(Process.getCurrentThreadId(), {
                events: {
                    exec: true
                },
                onReceive: function(events) {
                    const opcodes = Stalker.parse(events);

                    // Look for characteristic Themida VM patterns
                    let vmInstructions = 0;
                    opcodes.forEach(function(op) {
                        if (op.mnemonic === 'pushfd' || op.mnemonic === 'popfd') {
                            vmInstructions++;
                        }
                    });

                    if (vmInstructions > 10) {
                        send({
                            type: 'themida_vm_active'
                        });
                    }
                }
            });
        }, 1000);
        """

    def _generate_generic_unpacking_script(self) -> str:
        """Generate generic unpacking script."""
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
        """Apply all detected protection bypasses."""
        try:
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

            def on_message(message: object, data: object) -> None:
                if message["type"] == "send":
                    logger.info("Bypass result: %s", message["payload"])
                elif message["type"] == "error":
                    logger.exception("Bypass error: %s", message, exc_info=True)

            self.script.on("message", on_message)
            self.script.load()

            logger.info("Applied %s protection bypasses", len(all_scripts))
            return True

        except Exception as e:
            logger.exception("Failed to apply bypasses: %s", e, exc_info=True)
            return False

    def detect_all_protections(self) -> list[ProtectionInfo]:
        """Run all protection detection routines."""
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
            except Exception as e:
                logger.exception("Failed to detect %s: %s", name, e, exc_info=True)

        self.detected_protections = all_detections
        logger.info("Total protections detected: %s", len(all_detections))

        return all_detections

    def generate_bypass_report(self) -> str:
        """Generate detailed report of detected protections and bypasses."""
        report = [
            "=" * 60,
            "PROTECTION BYPASS ANALYSIS REPORT",
            "=" * 60,
            f"Target: {self.process_name or f'PID {self.pid}'}",
            f"Total Protections Detected: {len(self.detected_protections)}",
            "",
        ]
        # Group by protection type
        by_type = {}
        for protection in self.detected_protections:
            if protection.type not in by_type:
                by_type[protection.type] = []
            by_type[protection.type].append(protection)

        for prot_type, protections in by_type.items():
            report.extend(
                (
                    f"\n{prot_type.value.upper()} ({len(protections)} detected)",
                    "-" * 40,
                )
            )
            for i, prot in enumerate(protections, 1):
                report.extend(
                    (
                        f"  [{i}] Location: {prot.location}",
                        f"      Confidence: {prot.confidence:.1%}",
                        f"      Bypass Available: {'Yes' if prot.bypass_available else 'No'}",
                    )
                )
                for key, value in prot.details.items():
                    report.append(f"      {key}: {value}")

                report.append("")

        report.extend(("\n" + "=" * 60, "RECOMMENDATIONS", "=" * 60))
        if self.detected_protections:
            report.extend(
                (
                    "1. Apply all available bypasses using apply_all_bypasses()",
                    "2. Monitor application behavior after bypass",
                    "3. Use memory dumps for further analysis",
                    "4. Consider using automated unpacking for packed binaries",
                )
            )
        else:
            report.extend(
                (
                    "No protections detected. The target may use:",
                    "- Custom protection mechanisms",
                )
            )
            report.append("- Obfuscation without standard patterns")
            report.append("- Server-side license validation")

        return "\n".join(report)


def main() -> None:
    """Demonstrate usage of FridaProtectionBypasser."""
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
        logger.exception("Failed to attach to process")
        return

    # Detect all protections
    protections = bypasser.detect_all_protections()

    # Generate and display report
    report = bypasser.generate_bypass_report()
    print(report)

    # Save report if requested
    if args.report:
        with open(args.report, "w") as f:
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
