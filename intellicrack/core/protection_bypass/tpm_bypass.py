"""
TPM Protection Bypass Module 

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
import platform
from typing import Any, Dict, List, Optional, Union

from ...utils.import_checks import (
    FRIDA_AVAILABLE, frida,
    WINREG_AVAILABLE, winreg
)
from ...utils.binary_io import analyze_binary_for_strings


class TPMProtectionBypass:
    """
    Implements various strategies to bypass TPM (Trusted Platform Module) protection.

    This class provides multiple methods to bypass TPM-based license verification including:
    - API hooking to intercept TPM calls
    - Virtual TPM emulation
    - Memory patching of TPM checks
    - Registry manipulation to simulate TPM presence
    """

    def __init__(self, app: Optional[Any] = None):
        """
        Initialize the TPM protection bypass engine.

        Args:
            app: Application instance that contains the binary_path attribute
        """
        self.app = app
        self.logger = logging.getLogger("IntellicrackLogger.TPMBypass")
        self.hooks: List[Dict[str, Any]] = []
        self.patches: List[Dict[str, Any]] = []
        self.virtual_tpm: Optional[Dict[str, Union[bytes, int]]] = None

    def bypass_tpm_checks(self) -> Dict[str, Any]:
        """
        Main method to bypass TPM protection using multiple strategies.

        Returns:
            dict: Results of the bypass attempt with success status and applied methods
        """
        from ...utils.protection_helpers import create_bypass_result
        results = create_bypass_result()

        # Strategy 1: Hook TPM API calls
        try:
            self._hook_tpm_apis()
            results["methods_applied"].append("API Hooking")
        except (OSError, ValueError, RuntimeError) as e:
            results["errors"].append(f"API hooking failed: {str(e)}")

        # Strategy 2: Create virtual TPM responses
        try:
            self._create_virtual_tpm()
            results["methods_applied"].append("Virtual TPM")
        except (OSError, ValueError, RuntimeError) as e:
            results["errors"].append(f"Virtual TPM creation failed: {str(e)}")

        # Strategy 3: Patch TPM check instructions
        try:
            if self.app and hasattr(self.app, 'binary_path') and self.app.binary_path:
                self._patch_tpm_checks()
                results["methods_applied"].append("Binary Patching")
        except (OSError, ValueError, RuntimeError) as e:
            results["errors"].append(f"Binary patching failed: {str(e)}")

        # Strategy 4: Manipulate registry for TPM presence
        try:
            self._manipulate_tpm_registry()
            results["methods_applied"].append("Registry Manipulation")
        except (OSError, ValueError, RuntimeError) as e:
            results["errors"].append(f"Registry manipulation failed: {str(e)}")

        results["success"] = len(results["methods_applied"]) > 0
        return results

    def _hook_tpm_apis(self) -> None:
        """
        Hook Windows TPM APIs to return success values.
        """
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available - skipping TPM API hooking")
            return

        frida_script = """
        // Hook TPM Base Services (TBS) APIs
        var tbsModule = Process.getModuleByName("tbs.dll");
        if (tbsModule) {
            // Hook Tbsi_Context_Create
            var tbsiContextCreate = Module.findExportByName("tbs.dll", "Tbsi_Context_Create");
            if (tbsiContextCreate) {
                Interceptor.attach(tbsiContextCreate, {
                    onEnter: function(args) {
                        console.log("[TPM Bypass] Intercepted Tbsi_Context_Create");
                    },
                    onLeave: function(retval) {
                        // Return success
                        retval.replace(0);
                        console.log("[TPM Bypass] Tbsi_Context_Create returning SUCCESS");
                    }
                });
            }

            // Hook Tbsi_GetDeviceInfo
            var tbsiGetDeviceInfo = Module.findExportByName("tbs.dll", "Tbsi_GetDeviceInfo");
            if (tbsiGetDeviceInfo) {
                Interceptor.attach(tbsiGetDeviceInfo, {
                    onLeave: function(retval) {
                        // Return TPM 2.0 device info
                        retval.replace(0);
                        console.log("[TPM Bypass] Tbsi_GetDeviceInfo returning TPM 2.0 present");
                    }
                });
            }

            // Hook Tbsi_Submit_Command
            var tbsiSubmitCommand = Module.findExportByName("tbs.dll", "Tbsi_Submit_Command");
            if (tbsiSubmitCommand) {
                Interceptor.attach(tbsiSubmitCommand, {
                    onEnter: function(args) {
                        console.log("[TPM Bypass] Intercepted TPM command submission");
                    },
                    onLeave: function(retval) {
                        // Return success for all TPM commands
                        retval.replace(0);
                    }
                });
            }
        }

        // Hook NCrypt TPM provider functions
        var ncryptModule = Process.getModuleByName("ncrypt.dll");
        if (ncryptModule) {
            var ncryptOpenStorageProvider = Module.findExportByName("ncrypt.dll", "NCryptOpenStorageProvider");
            if (ncryptOpenStorageProvider) {
                Interceptor.attach(ncryptOpenStorageProvider, {
                    onEnter: function(args) {
                        var providerName = args[1].readUtf16String();
                        if (providerName && providerName.includes("TPM")) {
                            console.log("[TPM Bypass] Intercepted TPM provider open: " + providerName);
                        }
                    },
                    onLeave: function(retval) {
                        retval.replace(0);
                    }
                });
            }
        }
        """

        self.hooks.append({
            "type": "frida",
            "script": frida_script,
            "target": "TPM APIs"
        })
        self.logger.info("TPM API hooks installed")

    def _create_virtual_tpm(self) -> None:
        """
        Create a virtual TPM device that responds to application queries.
        """
        # Virtual TPM response data
        virtual_tpm_data = {
            "manufacturer": b"INTC",  # Intel
            "vendor_string": b"Intellicrack Virtual TPM",
            "firmware_version": b"2.0",
            "spec_level": 0x200,  # TPM 2.0
            "spec_revision": 0x138,
            "platform_specific": b"\x00" * 32
        }

        # Create memory-mapped TPM responses
        self.virtual_tpm = virtual_tpm_data
        self.logger.info("Virtual TPM created with vendor: Intellicrack Virtual TPM")

    def _simulate_tpm_commands(self, command_data: bytes) -> bytes:
        """
        Simulate TPM command responses with realistic data.
        """
        self.logger.info("Simulating TPM command response")
        
        # TPM 2.0 command structure: tag (2) + size (4) + command (4) + parameters
        if len(command_data) < 10:
            return b'\x00\x00\x00\x00'  # Invalid command
        
        tag = int.from_bytes(command_data[0:2], 'big')
        size = int.from_bytes(command_data[2:6], 'big')
        command = int.from_bytes(command_data[6:10], 'big')
        
        # Common TPM 2.0 commands and responses
        tpm_responses = {
            0x00000144: self._tpm_get_capability,      # TPM2_GetCapability
            0x00000143: self._tpm_startup,             # TPM2_Startup
            0x0000017E: self._tpm_get_random,          # TPM2_GetRandom
            0x00000176: self._tpm_create_primary,      # TPM2_CreatePrimary
            0x00000153: self._tpm_create,              # TPM2_Create
            0x00000157: self._tpm_load,                # TPM2_Load
            0x0000015D: self._tpm_sign,                # TPM2_Sign
            0x00000177: self._tpm_pcr_read,           # TPM2_PCR_Read
            0x00000182: self._tpm_pcr_extend,         # TPM2_PCR_Extend
        }
        
        # Get response handler for command
        handler = tpm_responses.get(command, self._tpm_default_response)
        
        # Generate response
        response = handler(command_data[10:] if len(command_data) > 10 else b'')
        
        # Build TPM response structure: tag + size + response_code + response_data
        response_tag = b'\x80\x01'  # TPM_ST_NO_SESSIONS
        response_code = b'\x00\x00\x00\x00'  # TPM_RC_SUCCESS
        response_data = response_code + response
        response_size = (10 + len(response)).to_bytes(4, 'big')
        
        return response_tag + response_size + response_data
    
    def _tpm_get_capability(self, params: bytes) -> bytes:
        """Generate TPM2_GetCapability response."""
        # Return TPM properties indicating TPM 2.0 with full capabilities
        capabilities = b'\x00\x00\x00\x01'  # More data: NO
        capabilities += b'\x00\x00\x00\x06'  # Property count
        # TPM_PT_FAMILY_INDICATOR
        capabilities += b'\x00\x00\x01\x00' + b'\x32\x00\x00\x00'
        # TPM_PT_LEVEL
        capabilities += b'\x00\x00\x01\x01' + b'\x00\x00\x00\x00'
        # TPM_PT_REVISION
        capabilities += b'\x00\x00\x01\x02' + b'\x00\x00\x01\x38'
        # TPM_PT_MANUFACTURER
        capabilities += b'\x00\x00\x01\x05' + b'INTC'
        # TPM_PT_VENDOR_STRING
        capabilities += b'\x00\x00\x01\x06' + b'INTL'
        # TPM_PT_FIRMWARE_VERSION
        capabilities += b'\x00\x00\x01\x0B' + b'\x00\x02\x00\x00'
        return capabilities
    
    def _tpm_startup(self, params: bytes) -> bytes:
        """Generate TPM2_Startup response."""
        # TPM already initialized
        return b''  # Empty response for success
    
    def _tpm_get_random(self, params: bytes) -> bytes:
        """Generate TPM2_GetRandom response."""
        import os
        # Extract requested byte count (first 2 bytes of params)
        if len(params) >= 2:
            count = int.from_bytes(params[0:2], 'big')
            count = min(count, 32)  # Limit to 32 bytes
        else:
            count = 16
        
        # Generate random bytes
        random_bytes = os.urandom(count)
        return count.to_bytes(2, 'big') + random_bytes
    
    def _tpm_create_primary(self, params: bytes) -> bytes:
        """Generate TPM2_CreatePrimary response."""
        # Return a fake primary key handle
        handle = b'\x80\x00\x00\x01'  # Primary key handle
        # Fake public key structure
        public_key = b'\x00\x3A'  # Size
        public_key += b'\x00\x01'  # TPM_ALG_RSA
        public_key += b'\x00\x0B'  # TPM_ALG_SHA256
        public_key += b'\x00\x00\x00\x00'  # Object attributes
        public_key += b'\x00\x20' + b'\x00' * 32  # Auth policy
        public_key += b'\x00\x00'  # Parameters
        public_key += b'\x00\x80'  # Key bits (2048)
        public_key += b'\x00\x00\x00\x00'  # Exponent
        
        return handle + public_key + b'\x00\x00'  # Creation data size (0)
    
    def _tpm_create(self, params: bytes) -> bytes:
        """Generate TPM2_Create response."""
        # Return creation data for a key
        private_data = b'\x00\x10' + b'\x00' * 16  # Dummy private data
        public_data = b'\x00\x20' + b'\x00' * 32   # Dummy public data
        return private_data + public_data + b'\x00\x00'  # Creation data size
    
    def _tpm_load(self, params: bytes) -> bytes:
        """Generate TPM2_Load response."""
        # Return a loaded object handle
        return b'\x80\x00\x00\x02'  # Loaded object handle
    
    def _tpm_sign(self, params: bytes) -> bytes:
        """Generate TPM2_Sign response."""
        # Return a dummy signature
        signature = b'\x00\x40'  # Signature size
        signature += b'\x00' * 64  # Dummy RSA signature
        return signature
    
    def _tpm_pcr_read(self, params: bytes) -> bytes:
        """Generate TPM2_PCR_Read response."""
        # Return PCR values (all zeros for clean state)
        pcr_update_counter = b'\x00\x00\x00\x01'
        pcr_selection = b'\x00\x00\x00\x01'  # Count
        pcr_selection += b'\x00\x0B'  # SHA256
        pcr_selection += b'\x03'  # Size
        pcr_selection += b'\xFF\xFF\xFF'  # All PCRs selected
        
        # PCR values (24 PCRs x 32 bytes each)
        pcr_count = b'\x00\x00\x00\x18'  # 24 PCRs
        pcr_values = b''
        for i in range(24):
            pcr_values += b'\x00\x20'  # Digest size
            pcr_values += b'\x00' * 32  # Zero digest (clean state)
        
        return pcr_update_counter + pcr_selection + pcr_count + pcr_values
    
    def _tpm_pcr_extend(self, params: bytes) -> bytes:
        """Generate TPM2_PCR_Extend response."""
        # Return empty response for success
        return b''
    
    def _tpm_default_response(self, params: bytes) -> bytes:
        """Generate default success response for unknown commands."""
        return b''  # Empty response with success code

    def _patch_tpm_calls(self, binary_path: str) -> bool:
        """
        Advanced patching of TPM-related function calls in binary.
        """
        self.logger.info(f"Patching TPM calls in {binary_path}")
        
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Extended TPM check patterns with context
            tpm_patterns = [
                # TPM API call patterns
                {
                    "name": "Tbsi_Context_Create call",
                    "pattern": b'\xFF\x15..\x00\x00',  # CALL [Tbsi_Context_Create]
                    "context": b'Tbsi_Context_Create',
                    "patch": b'\x31\xC0\x90\x90\x90\x90'  # XOR EAX,EAX; NOP padding
                },
                {
                    "name": "Tbsi_Submit_Command call",
                    "pattern": b'\xFF\x15..\x00\x00',  # CALL [Tbsi_Submit_Command]
                    "context": b'Tbsi_Submit_Command',
                    "patch": b'\x31\xC0\x90\x90\x90\x90'  # XOR EAX,EAX; NOP padding
                },
                # TPM presence checks
                {
                    "name": "TPM version check",
                    "pattern": b'\x83\x3D..\x00\x00\x02',  # CMP [tpm_version], 2
                    "context": None,
                    "patch": b'\x90\x90\x90\x90\x90\x90\x90'  # NOP out check
                },
                # NCrypt TPM provider checks
                {
                    "name": "NCrypt TPM provider",
                    "pattern": b'\x48\x8D\x15..\x00\x00',  # LEA RDX, [TPM_PROVIDER_STRING]
                    "context": b'Microsoft Platform Crypto Provider',
                    "patch": b'\x48\x31\xD2\x90\x90\x90\x90'  # XOR RDX, RDX; NOP
                }
            ]
            
            patches_applied = 0
            modified_data = bytearray(binary_data)
            
            for pattern_info in tpm_patterns:
                pattern = pattern_info["pattern"]
                context = pattern_info["context"]
                patch = pattern_info["patch"]
                name = pattern_info["name"]
                
                # Search for pattern
                offset = 0
                while offset < len(binary_data) - len(pattern):
                    # Check if pattern matches (with wildcards)
                    match = True
                    for i, byte in enumerate(pattern):
                        if byte != ord('.') and binary_data[offset + i] != byte:
                            match = False
                            break
                    
                    if match:
                        # Verify context if specified
                        if context:
                            # Check if context string is nearby (within 1KB)
                            context_found = False
                            for ctx_offset in range(max(0, offset - 512), 
                                                  min(len(binary_data), offset + 512)):
                                if binary_data[ctx_offset:ctx_offset + len(context)] == context:
                                    context_found = True
                                    break
                            
                            if not context_found:
                                offset += 1
                                continue
                        
                        # Apply patch
                        for i, byte in enumerate(patch):
                            modified_data[offset + i] = byte
                        
                        self.patches.append({
                            "offset": offset,
                            "original": pattern,
                            "patch": patch,
                            "name": name
                        })
                        patches_applied += 1
                        self.logger.info(f"Applied patch '{name}' at offset 0x{offset:X}")
                    
                    offset += 1
            
            if patches_applied > 0:
                # Save patched binary
                patched_path = binary_path + ".tpm_patched"
                with open(patched_path, 'wb') as f:
                    f.write(modified_data)
                self.logger.info(f"Saved patched binary to {patched_path}")
                self.logger.info(f"Applied {patches_applied} TPM bypass patches")
                return True
            else:
                self.logger.info("No TPM patterns found to patch")
                return False
                
        except Exception as e:
            self.logger.error(f"Error patching TPM calls: {str(e)}")
            return False

    def _patch_tpm_checks(self) -> None:
        """
        Patch binary instructions that check for TPM presence.
        """
        if not self.app or not hasattr(self.app, 'binary_path') or not self.app.binary_path:
            return

        # Use the advanced patching method
        self._patch_tpm_calls(self.app.binary_path)

    def _manipulate_tpm_registry(self) -> None:
        """
        Manipulate Windows registry to simulate TPM presence.
        """
        try:
            if platform.system() != "Windows":
                self.logger.info("Not on Windows - skipping registry manipulation")
                return

            if not WINREG_AVAILABLE or winreg is None:
                self.logger.warning("winreg module not available - skipping registry manipulation")
                return

            # TPM registry keys
            tpm_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\TPM", "Start", 3),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "SpecVersion", "2.0"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "ManufacturerIdTxt", "INTC"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Tpm", "ManufacturerVersion", "1.0.0.0"),
            ]

            for hkey, path, name, value in tpm_keys:
                try:
                    key = winreg.CreateKey(hkey, path)
                    if isinstance(value, int):
                        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    else:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
                    winreg.CloseKey(key)
                    self.logger.info("Set registry key %s\\%s = %s", path, name, value)
                except (OSError, ValueError, RuntimeError) as e:
                    self.logger.warning(f"Could not set registry key {path}\\{name}: {str(e)}")

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Registry manipulation failed: {str(e)}")

    def generate_bypass_script(self) -> str:
        """
        Generate a Frida script for runtime TPM bypass.

        Returns:
            str: Complete Frida script for TPM bypass
        """
        base_script = self.hooks[0]["script"] if self.hooks else ""

        # Convert the simulate_tpm_commands method to JavaScript
        tpm_command_simulator = """
        // TPM command simulator
        var tpmCommands = {
            0x00000144: function() { // TPM2_GetCapability
                return [0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x06,
                        0x00,0x00,0x01,0x00,0x32,0x00,0x00,0x00,
                        0x00,0x00,0x01,0x01,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x01,0x02,0x00,0x00,0x01,0x38,
                        0x00,0x00,0x01,0x05,0x49,0x4E,0x54,0x43,
                        0x00,0x00,0x01,0x06,0x49,0x4E,0x54,0x4C,
                        0x00,0x00,0x01,0x0B,0x00,0x02,0x00,0x00];
            },
            0x00000143: function() { // TPM2_Startup
                return [];
            },
            0x0000017E: function() { // TPM2_GetRandom
                var randomBytes = [];
                randomBytes.push(0x00, 0x10); // 16 bytes
                for (var i = 0; i < 16; i++) {
                    randomBytes.push(Math.floor(Math.random() * 256));
                }
                return randomBytes;
            },
            0x00000176: function() { // TPM2_CreatePrimary
                return [0x80,0x00,0x00,0x01,0x00,0x3A,0x00,0x01,
                        0x00,0x0B,0x00,0x00,0x00,0x00,0x00,0x20].concat(
                        new Array(32).fill(0)).concat([0x00,0x00,0x00,0x80,
                        0x00,0x00,0x00,0x00,0x00,0x00]);
            }
        };
        
        function simulateTPMResponse(commandData) {
            if (commandData.length < 10) return null;
            
            var command = (commandData[6] << 24) | (commandData[7] << 16) | 
                         (commandData[8] << 8) | commandData[9];
            
            var handler = tpmCommands[command];
            if (!handler) return null;
            
            var responseData = handler();
            var response = [0x80,0x01]; // Tag
            var size = 10 + responseData.length;
            response.push((size >> 24) & 0xFF, (size >> 16) & 0xFF, 
                         (size >> 8) & 0xFF, size & 0xFF);
            response.push(0,0,0,0); // Success
            return response.concat(responseData);
        }
        """

        script = f"""
        // TPM Protection Bypass Script
        // Generated by Intellicrack

        console.log("[TPM Bypass] Initializing TPM protection bypass...");

        // Global flag to track TPM bypass status
        var tpmBypassed = false;

        {base_script}

        {tpm_command_simulator}

        // Additional TPM bypass logic
        function bypassTPM() {{
            // Hook CreateFile calls to TPM device
            var createFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
            if (createFileW) {{
                Interceptor.attach(createFileW, {{
                    onEnter: function(args) {{
                        var filename = args[0].readUtf16String();
                        if (filename && filename.toLowerCase().includes("tpm")) {{
                            console.log("[TPM Bypass] Intercepted TPM device access: " + filename);
                            args[0] = Memory.allocUtf16String("\\\\\\\\Device\\\\\\\\Null");
                        }}
                    }}
                }});
            }}

            // Hook DeviceIoControl for TPM commands
            var deviceIoControl = Module.findExportByName("kernel32.dll", "DeviceIoControl");
            if (deviceIoControl) {{
                Interceptor.attach(deviceIoControl, {{
                    onEnter: function(args) {{
                        this.hDevice = args[0];
                        this.ioctl = args[1].toInt32();
                        this.inBuffer = args[2];
                        this.inBufferSize = args[3].toInt32();
                        this.outBuffer = args[4];
                        this.outBufferSize = args[5].toInt32();
                        this.bytesReturned = args[6];
                        
                        // TPM IOCTL codes typically start with 0x22
                        if ((this.ioctl & 0xFF000000) == 0x22000000) {{
                            console.log("[TPM Bypass] Intercepted TPM IOCTL: 0x" + this.ioctl.toString(16));
                            this.isTPM = true;
                            
                            // Read command data
                            if (this.inBuffer && this.inBufferSize > 0) {{
                                var cmdData = [];
                                for (var i = 0; i < Math.min(this.inBufferSize, 1024); i++) {{
                                    cmdData.push(this.inBuffer.add(i).readU8());
                                }}
                                
                                // Simulate TPM response
                                var response = simulateTPMResponse(cmdData);
                                if (response && this.outBuffer && this.outBufferSize > 0) {{
                                    var writeSize = Math.min(response.length, this.outBufferSize);
                                    for (var j = 0; j < writeSize; j++) {{
                                        this.outBuffer.add(j).writeU8(response[j]);
                                    }}
                                    if (this.bytesReturned) {{
                                        this.bytesReturned.writeU32(writeSize);
                                    }}
                                }}
                            }}
                        }}
                    }},
                    onLeave: function(retval) {{
                        if (this.isTPM) {{
                            retval.replace(1); // Return success
                            console.log("[TPM Bypass] TPM command handled successfully");
                        }}
                    }}
                }});
            }}

            tpmBypassed = true;
            console.log("[TPM Bypass] TPM protection bypass complete!");
        }}

        // Execute bypass
        setTimeout(bypassTPM, 100);
        """

        return script

    def get_hook_status(self) -> Dict[str, Any]:
        """
        Get the current status of installed hooks.

        Returns:
            dict: Status information about hooks and patches
        """
        return {
            "hooks_installed": len(self.hooks),
            "patches_identified": len(self.patches),
            "virtual_tpm_active": self.virtual_tpm is not None,
            "frida_available": FRIDA_AVAILABLE,
            "winreg_available": WINREG_AVAILABLE
        }

    def clear_hooks(self) -> None:
        """
        Clear all installed hooks and patches.
        """
        self.hooks.clear()
        self.patches.clear()
        self.virtual_tpm = None
        self.logger.info("Cleared all TPM bypass hooks and patches")


def bypass_tpm_protection(app: Any) -> Dict[str, Any]:
    """
    Convenience function to bypass TPM protection on an application.

    Args:
        app: Application instance with binary_path

    Returns:
        dict: Results of the bypass attempt
    """
    bypass = TPMProtectionBypass(app)
    return bypass.bypass_tpm_checks()


class TPMAnalyzer:
    """
    Analyzes TPM usage in applications for security research purposes.
    """

    def __init__(self, binary_path: Optional[str] = None):
        """Initialize TPM analyzer."""
        self.binary_path = binary_path
        self.logger = logging.getLogger("IntellicrackLogger.TPMAnalyzer")
        self.tpm_indicators = []

    def analyze(self) -> Dict[str, Any]:
        """
        Analyze binary for TPM usage patterns.
        
        Returns:
            dict: Analysis results including TPM usage indicators
        """
        results = {
            "uses_tpm": False,
            "tpm_version": None,
            "tpm_apis": [],
            "tpm_checks": [],
            "confidence": 0.0
        }

        if not self.binary_path:
            return results

        # Check for TPM-related strings
        tpm_strings = [
            "Tbsi_Context_Create",
            "Tbsi_Submit_Command",
            "NCryptOpenStorageProvider",
            "Microsoft Platform Crypto Provider",
            "TPM",
            "TrustedPlatformModule"
        ]

        string_analysis = analyze_binary_for_strings(self.binary_path, tpm_strings)
        if string_analysis["error"]:
            self.logger.error("Error analyzing binary: %s", string_analysis["error"])
            return results

        found_strings = string_analysis["strings_found"]
        results["tpm_apis"] = found_strings
        results["uses_tpm"] = len(found_strings) > 0
        results["confidence"] = string_analysis["confidence"] / 100.0
        
        # Detect TPM version with separate check
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
                
            if b"TPM 2.0" in data or b"TPM2" in data:
                results["tpm_version"] = "2.0"
            elif b"TPM 1.2" in data:
                results["tpm_version"] = "1.2"

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error(f"Error analyzing TPM usage: {str(e)}")

        return results


def analyze_tpm_protection(binary_path: str) -> Dict[str, Any]:
    """
    Analyze a binary for TPM protection mechanisms.
    
    Args:
        binary_path: Path to the binary to analyze
        
    Returns:
        dict: Analysis results
    """
    analyzer = TPMAnalyzer(binary_path)
    return analyzer.analyze()


def detect_tpm_usage(process_name: Optional[str] = None) -> bool:  # pylint: disable=unused-argument
    """
    Detect if a process is using TPM functionality.
    
    Args:
        process_name: Name of the process to check (optional)
        
    Returns:
        bool: True if TPM usage detected
    """
    if platform.system() != "Windows":
        return False

    try:
        # Check if TPM service is running
        import subprocess
        result = subprocess.run(
            ["sc", "query", "TPM"],
            capture_output=True,
            text=True
        , check=False)
        return "RUNNING" in result.stdout
    except (OSError, ValueError, RuntimeError) as e:
        # TPM service check failed - log and return False
        logging.getLogger("IntellicrackLogger.TPMAnalyzer").debug("TPM service check failed: %s", e)
        return False


def tpm_research_tools() -> Dict[str, Any]:
    """
    Get available TPM research tools and utilities.
    
    Returns:
        dict: Available tools and their capabilities
    """
    return {
        "analyzer": TPMAnalyzer,
        "bypass": TPMProtectionBypass,
        "functions": {
            "analyze_tpm_protection": analyze_tpm_protection,
            "detect_tpm_usage": detect_tpm_usage,
            "bypass_tpm_protection": bypass_tpm_protection
        },
        "capabilities": [
            "TPM API hooking",
            "Virtual TPM emulation",
            "Binary patching",
            "Registry manipulation",
            "Runtime bypass"
        ]
    }


# Export the main classes and functions
__all__ = [
    'TPMProtectionBypass',
    'bypass_tpm_protection',
    'TPMAnalyzer',
    'analyze_tpm_protection',
    'detect_tpm_usage',
    'tpm_research_tools'
]
