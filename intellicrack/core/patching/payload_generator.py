"""
Advanced Payload Generation Module 

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


import logging
import random
import traceback
from typing import Any, Dict, Optional

try:
    import keystone
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    keystone = None

from ...utils.logger import get_logger

logger = get_logger(__name__)

class PayloadGenerator:
    """
    Basic payload generator for creating patches and shellcode.
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def generate_nop_sled(self, length: int) -> bytes:
        """
        Generate a NOP sled of specified length.

        Args:
            length: Length of NOP sled in bytes

        Returns:
            bytes: NOP sled
        """
        return b'\x90' * length

    def generate_simple_payload(self, payload_type: str) -> Optional[bytes]:
        """
        Generate a simple payload of the specified type.

        Args:
            payload_type: Type of payload to generate

        Returns:
            Optional[bytes]: Generated payload or None if type not supported
        """
        payloads = {
            'ret_1': b'\xb8\x01\x00\x00\x00\xc3',  # mov eax, 1; ret
            'ret_0': b'\x31\xc0\xc3',                # xor eax, eax; ret
            'infinite_loop': b'\xeb\xfe',            # jmp $
        }

        return payloads.get(payload_type)


class AdvancedPayloadGenerator:
    """
    Sophisticated payload generation for exploit strategies
    """

    def __init__(self):
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    def generate_license_bypass_payload(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Generate advanced license bypass payloads.

        Creates specialized machine code payloads designed to bypass license protection
        mechanisms based on the provided exploitation strategy. Selects the appropriate
        payload generator based on the strategy type (function hijacking, memory manipulation,
        license validation bypass, cryptographic bypass, or generic bypass).

        Args:
            strategy: Dictionary containing the exploitation strategy details

        Returns:
            bytes: Assembled machine code payload ready for injection or patching
        """
        self.logger.info(f"Generating license bypass payload for strategy: {strategy.get('strategy', 'generic_bypass')}")

        payload_generators = {
            'function_hijacking': self._function_hijack_payload,
            'memory_manipulation': self._memory_manipulation_payload,
            'license_bypass': self._license_validation_bypass,
            'cryptographic_bypass': self._crypto_bypass_payload,
            'generic_bypass': self._generic_bypass_payload
        }

        generator = payload_generators.get(
            strategy.get('strategy', 'generic_bypass'),
            self._generic_bypass_payload
        )

        self.logger.debug("Selected generator: %s", generator.__name__)

        payload_bytes = generator(strategy)
        if payload_bytes:
            self.logger.info(f"Generated payload of length {len(payload_bytes)} bytes.")
        else:
            self.logger.error("Failed to generate payload")
        return payload_bytes

    def _function_hijack_payload(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Generate payload to hijack critical functions.

        Creates x86-64 assembly code that replaces the functionality of targeted functions,
        typically forcing them to return success values regardless of input parameters.
        Used to bypass license validation or security check functions.

        Args:
            strategy: Dictionary containing details about the function to hijack

        Returns:
            bytes: Assembled machine code ready for injection at the target function address
        """
        self.logger.debug("Generating function hijack payload for strategy: %s", strategy)

        hijack_template = """
        mov rax, 1      ; Return success
        ret             ; Return from function
        """

        return self._assemble_x86_64(hijack_template)

    def _memory_manipulation_payload(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Generate memory manipulation payload.

        Creates specialized machine code for modifying memory regions containing
        license validation logic or protected data. Uses techniques like NOP slides
        and register manipulation to bypass protection mechanisms.

        Args:
            strategy: Dictionary containing details about the memory region to manipulate

        Returns:
            bytes: Assembled machine code for memory manipulation
        """
        self.logger.debug("Generating memory manipulation payload for strategy: %s", strategy)

        manipulation_templates = [
            """
            nop             ; No-operation sled
            nop
            nop
            mov rax, 1      ; Return success
            ret             ; Return from function
            """,
            """
            push 1           ; Push success value to stack
            pop rax          ; Pop into return register
            ret              ; Return from function
            """
        ]

        template = random.choice(manipulation_templates)
        return self._assemble_x86_64(template)

    def _license_validation_bypass(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Generate sophisticated license validation bypass payload.

        Creates specialized machine code specifically designed to bypass license
        validation routines. Uses multiple techniques including register manipulation,
        constant return values, and stack manipulation to ensure license checks
        always return success regardless of actual license status.

        Args:
            strategy: Dictionary containing details about the license validation to bypass

        Returns:
            bytes: Assembled machine code payload optimized for license validation bypass
        """
        self.logger.debug("Generating license validation bypass payload for strategy: %s", strategy)

        bypass_techniques = [
            """
            xor rax, rax    ; Zero out return register
            inc rax         ; Set to 1 (success)
            ret             ; Return from function
            """,
            """
            mov rax, 0x7FFFFFFFFFFFFFFF  ; Large positive value
            ret              ; Return from function
            """,
            """
            push 1           ; Push success value to stack
            pop rax          ; Pop into return register
            ret              ; Return from function
            """
        ]

        template = random.choice(bypass_techniques)
        return self._assemble_x86_64(template)

    def _crypto_bypass_payload(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Generate advanced cryptographic bypass payload.

        Creates machine code designed to bypass cryptographic verification routines
        by returning hardcoded "valid" keys or hash values. Targets cryptographic
        validation functions to make them always return success regardless of input.

        Args:
            strategy: Dictionary containing details about the cryptographic mechanism to bypass

        Returns:
            bytes: Assembled machine code payload for cryptographic validation bypass
        """
        self.logger.debug("Generating crypto bypass payload for strategy: %s", strategy)

        crypto_bypass_techniques = [
            """
            ; Crypto bypass technique 1
            mov rax, 0x0123456789ABCDEF  ; Hardcoded "valid" key
            ret
            """,
            """
            ; Crypto bypass technique 2
            push 0x1                     ; Push constant "valid" value
            pop rax
            ret
            """
        ]

        template = random.choice(crypto_bypass_techniques)
        return self._assemble_x86_64(template)

    def _generic_bypass_payload(self, strategy: Dict[str, Any]) -> Optional[bytes]:
        """
        Fallback generic bypass payload.

        Creates a general-purpose bypass payload when specific vulnerability details
        are insufficient for a targeted approach. Implements common bypass techniques
        that work across various protection mechanisms by forcing success return values.

        Args:
            strategy: Dictionary containing general information about the protection to bypass

        Returns:
            bytes: Assembled machine code payload with generic bypass techniques
        """
        self.logger.debug("Generating generic bypass payload for strategy: %s", strategy)

        generic_techniques = [
            """
            mov rax, 1      ; Set return to success
            ret             ; Return from function
            """,
            """
            xor rax, rax    ; Zero register
            inc rax         ; Increment to 1
            ret             ; Return from function
            """
        ]

        template = random.choice(generic_techniques)
        return self._assemble_x86_64(template)

    def _assemble_x86_64(self, assembly_code: str) -> Optional[bytes]:
        """
        Assemble x86-64 assembly to machine code.

        Converts human-readable x86-64 assembly language instructions into binary
        machine code that can be directly executed by the processor. Uses the Keystone
        engine for reliable assembly with proper encoding.

        Args:
            assembly_code: String containing x86-64 assembly instructions

        Returns:
            bytes: Assembled machine code ready for injection or patching if successful,
                   None if assembly fails
        """
        if not assembly_code or not assembly_code.strip():
            self.logger.error("Empty assembly code provided to _assemble_x86_64")
            return None

        if not KEYSTONE_AVAILABLE:
            self.logger.error("Keystone engine not available for assembly")
            return None

        try:
            formatted_assembly = "\n".join(f"{i+1}: {line}" for i, line in enumerate(assembly_code.split('\n')))
            self.logger.debug("Assembling x86_64 code:\n%s", formatted_assembly)

            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            encoding, count = ks.asm(assembly_code)

            if not encoding:
                self.logger.warning("Assembly produced empty encoding for code:\n%s", formatted_assembly)
                return None

            self.logger.debug(f"Successfully assembled {count} instructions ({len(encoding)} bytes)")
            return bytes(encoding)

        except (OSError, ValueError, RuntimeError) as e:
            error_trace = traceback.format_exc()
            self.logger.error("Assembly error: %s", e)
            self.logger.debug("Assembly error traceback:\n%s", error_trace)
            return None


# Convenience functions
def generate_payload(payload_type: str, **kwargs) -> Optional[bytes]:  # pylint: disable=unused-argument
    """
    Generate a payload using the default generator.

    Args:
        payload_type: Type of payload to generate
        **kwargs: Additional arguments

    Returns:
        Optional[bytes]: Generated payload
    """
    generator = PayloadGenerator()
    return generator.generate_simple_payload(payload_type)

def generate_advanced_payload(strategy: Dict[str, Any]) -> Optional[bytes]:
    """
    Generate an advanced payload using the AdvancedPayloadGenerator.

    Args:
        strategy: Strategy dictionary for payload generation

    Returns:
        Optional[bytes]: Generated payload
    """
    generator = AdvancedPayloadGenerator()
    return generator.generate_license_bypass_payload(strategy)

def apply_patch(binary_data: bytes, offset: int, patch_data: bytes) -> bytes:
    """
    Apply a patch to binary data.

    Args:
        binary_data: Original binary data
        offset: Offset to apply patch
        patch_data: Patch data to apply

    Returns:
        bytes: Patched binary data
    """
    return binary_data[:offset] + patch_data + binary_data[offset + len(patch_data):]

def create_nop_sled(length: int) -> bytes:
    """
    Create a NOP sled of specified length.

    Args:
        length: Length in bytes

    Returns:
        bytes: NOP sled
    """
    generator = PayloadGenerator()
    return generator.generate_nop_sled(length)

def generate_complete_api_hooking_script(app, hook_types=None) -> str:
    """
    Generate comprehensive Frida API hooking scripts for various protection bypass types.

    Args:
        app: Application instance
        hook_types: List of hook types to include (hardware_id, debugger, time, network)

    Returns:
        str: Frida script for API hooking
    """
    if hook_types is None:
        hook_types = ["hardware_id", "debugger", "time", "network"]

    script_parts = []

    # Base script setup
    script_parts.append("""
        console.log('[Intellicrack] Comprehensive API hooking script loaded');

        // Global variables for tracking
        var hooksInstalled = {};
        var spoofedValues = {};
    """)

    # HWID Spoofing hooks
    if "hardware_id" in hook_types:
        script_parts.append("""
        // === HWID SPOOFING HOOKS ===
        console.log('[HWID] Installing hardware ID spoofing hooks...');

        // Spoof GetVolumeInformation (drive serial numbers)
        var getVolumeInfo = Module.findExportByName("kernel32.dll", "GetVolumeInformationW");
        if (getVolumeInfo) {
            Interceptor.attach(getVolumeInfo, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Modify volume serial number
                        var serialPtr = this.context.r8; // 5th parameter (dwVolumeSerialNumber)
                        if (serialPtr && !serialPtr.isNull()) {
                            serialPtr.writeU32(0x12345678); // Spoofed serial
                            console.log('[HWID] Spoofed volume serial number to 0x12345678');
                        }
                    }
                }
            });
            hooksInstalled['GetVolumeInformation'] = true;
        }

        // Spoof GetAdaptersInfo (MAC addresses)
        var getAdaptersInfo = Module.findExportByName("iphlpapi.dll", "GetAdaptersInfo");
        if (getAdaptersInfo) {
            Interceptor.attach(getAdaptersInfo, {
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // NO_ERROR
                        var adapterInfo = this.context.rcx; // First parameter
                        if (adapterInfo && !adapterInfo.isNull()) {
                            // Replace MAC address with spoofed one
                            var macAddr = adapterInfo.add(8); // Address offset in IP_ADAPTER_INFO
                            macAddr.writeByteArray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                            console.log('[HWID] Spoofed MAC address to 00:11:22:33:44:55');
                        }
                    }
                }
            });
            hooksInstalled['GetAdaptersInfo'] = true;
        }

        // Spoof GetSystemInfo (processor information)
        var getSystemInfo = Module.findExportByName("kernel32.dll", "GetSystemInfo");
        if (getSystemInfo) {
            Interceptor.attach(getSystemInfo, {
                onLeave: function(retval) {
                    var sysInfo = this.context.rcx; // SYSTEM_INFO pointer
                    if (sysInfo && !sysInfo.isNull()) {
                        // Modify processor architecture and count
                        sysInfo.writeU16(9); // PROCESSOR_ARCHITECTURE_AMD64
                        sysInfo.add(4).writeU32(8); // dwNumberOfProcessors
                        console.log('[HWID] Spoofed processor information');
                    }
                }
            });
            hooksInstalled['GetSystemInfo'] = true;
        }

        console.log('[HWID] Hardware ID spoofing hooks installed');
        """)

    # Anti-debugger hooks
    if "debugger" in hook_types:
        script_parts.append("""
        // === ANTI-DEBUGGER COUNTERMEASURES ===
        console.log('[Anti-Debug] Installing anti-debugger countermeasures...');

        // Hook IsDebuggerPresent
        var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
                console.log('[Anti-Debug] IsDebuggerPresent called - returning FALSE');
                return 0; // FALSE
            }, 'int', []));
            hooksInstalled['IsDebuggerPresent'] = true;
        }

        // Hook CheckRemoteDebuggerPresent
        var checkRemoteDebugger = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
        if (checkRemoteDebugger) {
            Interceptor.attach(checkRemoteDebugger, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        // Set pbDebuggerPresent to FALSE
                        var pbDebugger = this.context.r8; // Second parameter
                        if (pbDebugger && !pbDebugger.isNull()) {
                            pbDebugger.writeU8(0); // FALSE
                            console.log('[Anti-Debug] CheckRemoteDebuggerPresent spoofed to FALSE');
                        }
                    }
                }
            });
            hooksInstalled['CheckRemoteDebuggerPresent'] = true;
        }

        // Hook NtQueryInformationProcess for debug flags
        var ntQueryInfo = Module.findExportByName("ntdll.dll", "NtQueryInformationProcess");
        if (ntQueryInfo) {
            Interceptor.attach(ntQueryInfo, {
                onEnter: function(args) {
                    this.infoClass = args[1].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0) { // STATUS_SUCCESS
                        // ProcessDebugPort = 7, ProcessDebugFlags = 31
                        if (this.infoClass === 7 || this.infoClass === 31) {
                            var buffer = this.context.r8; // ProcessInformation parameter
                            if (buffer && !buffer.isNull()) {
                                buffer.writeU32(0); // No debug port/flags
                                console.log('[Anti-Debug] NtQueryInformationProcess debug check bypassed');
                            }
                        }
                    }
                }
            });
            hooksInstalled['NtQueryInformationProcess'] = true;
        }

        // Hook OutputDebugString
        var outputDebugStringA = Module.findExportByName("kernel32.dll", "OutputDebugStringA");
        if (outputDebugStringA) {
            Interceptor.replace(outputDebugStringA, new NativeCallback(function(lpOutputString) {
                // Do nothing - prevent debug output
                return;
            }, 'void', ['pointer']));
            hooksInstalled['OutputDebugStringA'] = true;
        }

        console.log('[Anti-Debug] Anti-debugger countermeasures installed');
        """)

    # Time bomb defuser hooks
    if "time" in hook_types:
        script_parts.append("""
        // === TIME BOMB DEFUSER ===
        console.log('[Time Bomb] Installing time bomb defuser hooks...');

        // Hook GetSystemTime
        var getSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
        if (getSystemTime) {
            Interceptor.attach(getSystemTime, {
                onLeave: function(retval) {
                    var systemTime = this.context.rcx; // SYSTEMTIME pointer
                    if (systemTime && !systemTime.isNull()) {
                        // Set to a safe date: January 1, 2020
                        systemTime.writeU16(2020);      // wYear
                        systemTime.add(2).writeU16(1);  // wMonth
                        systemTime.add(6).writeU16(1);  // wDay
                        console.log('[Time Bomb] GetSystemTime spoofed to January 1, 2020');
                    }
                }
            });
            hooksInstalled['GetSystemTime'] = true;
        }

        // Hook GetLocalTime  
        var getLocalTime = Module.findExportByName("kernel32.dll", "GetLocalTime");
        if (getLocalTime) {
            Interceptor.attach(getLocalTime, {
                onLeave: function(retval) {
                    var localTime = this.context.rcx; // SYSTEMTIME pointer
                    if (localTime && !localTime.isNull()) {
                        // Set to a safe date: January 1, 2020
                        localTime.writeU16(2020);      // wYear
                        localTime.add(2).writeU16(1);  // wMonth
                        localTime.add(6).writeU16(1);  // wDay
                        console.log('[Time Bomb] GetLocalTime spoofed to January 1, 2020');
                    }
                }
            });
            hooksInstalled['GetLocalTime'] = true;
        }

        // Hook GetTickCount and GetTickCount64
        var getTickCount = Module.findExportByName("kernel32.dll", "GetTickCount");
        if (getTickCount) {
            var baseTime = Date.now();
            Interceptor.replace(getTickCount, new NativeCallback(function() {
                var elapsed = Date.now() - baseTime;
                return Math.floor(elapsed); // Return consistent tick count
            }, 'uint32', []));
            hooksInstalled['GetTickCount'] = true;
        }

        // Hook time() function from CRT
        var timeFunc = Module.findExportByName("msvcrt.dll", "time");
        if (timeFunc) {
            Interceptor.replace(timeFunc, new NativeCallback(function(timer) {
                var safeTime = Math.floor(new Date('2020-01-01').getTime() / 1000);
                if (timer && !timer.isNull()) {
                    timer.writeU32(safeTime);
                }
                console.log('[Time Bomb] time() function spoofed to safe date');
                return safeTime;
            }, 'uint32', ['pointer']));
            hooksInstalled['time'] = true;
        }

        console.log('[Time Bomb] Time bomb defuser hooks installed');
        """)

    # Telemetry blocking hooks
    if "network" in hook_types:
        script_parts.append("""
        // === TELEMETRY BLOCKING ===
        console.log('[Telemetry] Installing telemetry blocking hooks...');

        // Block HTTP/HTTPS requests to telemetry endpoints
        var winHttpOpen = Module.findExportByName("winhttp.dll", "WinHttpOpen");
        if (winHttpOpen) {
            Interceptor.attach(winHttpOpen, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        console.log('[Telemetry] WinHTTP session opened - monitoring enabled');
                        spoofedValues['winHttpSession'] = retval;
                    }
                }
            });
        }

        var winHttpConnect = Module.findExportByName("winhttp.dll", "WinHttpConnect");
        if (winHttpConnect) {
            Interceptor.attach(winHttpConnect, {
                onEnter: function(args) {
                    var serverName = args[1].readUtf16String();

                    // Block known telemetry domains
                    var blockedDomains = [
                        'telemetry.microsoft.com',
                        'vortex.data.microsoft.com',
                        'settings-win.data.microsoft.com',
                        'watson.microsoft.com',
                        'adobe.com/activation',
                        'genuine.microsoft.com'
                    ];

                    for (var domain of blockedDomains) {
                        if (serverName && serverName.toLowerCase().includes(domain)) {
                            console.log('[Telemetry] Blocked connection to: ' + serverName);
                            this.replace = true;
                            return;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.replace) {
                        retval.replace(ptr(0)); // Return NULL to indicate failure
                    }
                }
            });
            hooksInstalled['WinHttpConnect'] = true;
        }

        // Block Winsock connections
        var wsaConnect = Module.findExportByName("ws2_32.dll", "WSAConnect");
        if (wsaConnect) {
            Interceptor.attach(wsaConnect, {
                onEnter: function(args) {
                    var sockAddr = args[1];
                    if (sockAddr && !sockAddr.isNull()) {
                        var family = sockAddr.readU16();
                        if (family === 2) { // AF_INET
                            var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                            var ip = sockAddr.add(4).readU32();

                            // Block common telemetry ports
                            if (port === 80 || port === 443 || port === 8080) {
                                console.log('[Telemetry] Blocked WSA connection to port ' + port);
                                this.block = true;
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.block) {
                        retval.replace(-1); // SOCKET_ERROR
                    }
                }
            });
            hooksInstalled['WSAConnect'] = true;
        }

        console.log('[Telemetry] Telemetry blocking hooks installed');
        """)

    # Summary and completion
    script_parts.append("""
        // === INSTALLATION SUMMARY ===
        setTimeout(function() {
            console.log('[Intellicrack] API Hooking Summary:');
            for (var hook in hooksInstalled) {
                console.log('  ✓ ' + hook + ' hook installed');
            }
            console.log('[Intellicrack] All requested API hooks are now active!');
        }, 100);

        // Utility function to check hook status
        function getHookStatus() {
            return hooksInstalled;
        }
    """)

    final_script = '\n'.join(script_parts)

    if hasattr(app, 'update_output'):
        hook_names = []
        if "hardware_id" in hook_types:
            hook_names.append("HWID Spoofing")
        if "debugger" in hook_types:
            hook_names.append("Anti-Debugger Countermeasures")
        if "time" in hook_types:
            hook_names.append("Time Bomb Defuser")
        if "network" in hook_types:
            hook_names.append("Telemetry Blocking")

        app.update_output.emit(f"[Payload] Generated API hooking script for: {', '.join(hook_names)}")

    return final_script

def inject_shellcode(binary_data: bytes, shellcode: bytes, injection_point: int) -> bytes:
    """
    Inject shellcode into binary data.

    Args:
        binary_data: Original binary data
        shellcode: Shellcode to inject
        injection_point: Point to inject shellcode

    Returns:
        bytes: Modified binary data
    """
    return apply_patch(binary_data, injection_point, shellcode)


# Export functions
__all__ = [
    'PayloadGenerator',
    'apply_patch',
    'create_nop_sled',
    'inject_shellcode',
    'generate_complete_api_hooking_script',
]
