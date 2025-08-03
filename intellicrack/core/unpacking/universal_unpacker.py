"""
Universal Unpacker Engine

Advanced unpacking engine with hybrid dynamic-first approach using Frida and angr
for modern protections including VMProtect 3.x, Themida 3.x, and Denuvo.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import angr
import frida
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import lief
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from ...utils.logger import logger
from ..exploitation.memory_framework import DirectSyscallManager, AdvancedMemoryOperations
from .oep_detection import OEPDetector

logger = logging.getLogger(__name__)


class ProtectionType(Enum):
    """Protection scheme types"""
    UNKNOWN = "unknown"
    UPX = "upx"
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    DENUVO = "denuvo"
    OBSIDIUM = "obsidium"
    ENIGMA = "enigma"
    SAFENET = "safenet"
    ARMADILLO = "armadillo"


@dataclass
class UnpackingResult:
    """Result of unpacking operation"""
    success: bool
    unpacked_data: Optional[bytes] = None
    original_entry_point: Optional[int] = None
    unpacked_size: int = 0
    protection_type: Optional[ProtectionType] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None
    memory_dumps: List[bytes] = None
    api_calls: List[Dict[str, Any]] = None


@dataclass
class ProtectionSignature:
    """Protection scheme signature"""
    name: str
    patterns: List[bytes]
    masks: List[str]
    section_names: List[str]
    import_hints: List[str]
    entropy_threshold: float
    confidence_score: float = 0.0


class ProtectionDetector:
    """Advanced protection scheme detection"""
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
    
    def _initialize_signatures(self) -> Dict[ProtectionType, ProtectionSignature]:
        """Initialize protection signatures"""
        return {
            ProtectionType.VMPROTECT: ProtectionSignature(
                name="VMProtect",
                patterns=[
                    b"\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x58\x83\xC0\x05",
                    b"\x9C\x60\xE8\x00\x00\x00\x00\x5D\x81\xED",
                    b"\x68\x00\x00\x00\x00\xC3\x8B\x85\x00\x00\x00\x00\x30",
                ],
                masks=[
                    "x????x????xxxx",
                    "xxx????xxxxx",
                    "x????xxx????x",
                ],
                section_names=[".vmp0", ".vmp1", ".vmp2", "VMProtect"],
                import_hints=["VMProtectBegin", "VMProtectEnd"],
                entropy_threshold=7.8
            ),
            ProtectionType.THEMIDA: ProtectionSignature(
                name="Themida",
                patterns=[
                    b"\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x60\x8B",
                    b"\x68\x00\x00\x00\x00\xFF\x35\x00\x00\x00\x00\xE8",
                    b"\x50\x53\x51\x52\x56\x57\x8B\xF4\x8B\x7C\x24",
                ],
                masks=[
                    "x????x????xx",
                    "x????xx????x",
                    "xxxxxxxxxxx",
                ],
                section_names=[".themida", ".winlice", "Themida"],
                import_hints=["SecureEngine", "VM_", "FISH_"],
                entropy_threshold=7.9
            ),
            ProtectionType.DENUVO: ProtectionSignature(
                name="Denuvo",
                patterns=[
                    b"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18",
                    b"\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\x48\x85\xC9",
                    b"\x48\x83\xEC\x28\x48\x85\xC9\x0F\x84",
                ],
                masks=[
                    "xxxxxxxxxxxxxxx",
                    "xxxxxxxxxxxx",
                    "xxxxxxxxx",
                ],
                section_names=[".denuvo", ".steam_api", "steam_api64"],
                import_hints=["steam_api", "SteamAPI_"],
                entropy_threshold=7.7
            ),
            ProtectionType.UPX: ProtectionSignature(
                name="UPX",
                patterns=[
                    b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\x00\x00\x57\x83\xCD",
                    b"\x31\xDB\x8D\x7E\x10\x8D\x46\x0C\x01\xF8\x8D\x4E\x08",
                ],
                masks=[
                    "xx????xx????xxx",
                    "xxxxxxxxxxxxx",
                ],
                section_names=["UPX0", "UPX1", "UPX2"],
                import_hints=["__upx_"],
                entropy_threshold=6.5
            ),
        }
    
    def detect_protection(self, file_path: str) -> List[ProtectionType]:
        """Detect protection schemes in binary"""
        detected = []
        
        try:
            # Load binary
            binary = lief.parse(file_path)
            if not binary:
                return detected
            
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Check each protection type
            for prot_type, signature in self.signatures.items():
                confidence = self._calculate_confidence(file_data, binary, signature)
                if confidence > 0.6:  # 60% confidence threshold
                    detected.append(prot_type)
                    logger.info(f"Detected {signature.name} with {confidence:.2%} confidence")
            
            return detected
            
        except Exception as e:
            logger.error(f"Protection detection failed: {e}")
            return detected
    
    def _calculate_confidence(self, file_data: bytes, binary: Any, 
                            signature: ProtectionSignature) -> float:
        """Calculate detection confidence score"""
        confidence = 0.0
        total_checks = 4  # Pattern, section, import, entropy checks
        
        # Pattern matching
        pattern_matches = self._search_patterns(file_data, signature.patterns, signature.masks)
        if pattern_matches:
            confidence += 0.4  # 40% weight for patterns
        
        # Section name checks
        if hasattr(binary, 'sections'):
            for section in binary.sections:
                if any(hint.lower() in section.name.lower() for hint in signature.section_names):
                    confidence += 0.2  # 20% weight for sections
                    break
        
        # Import hints
        if hasattr(binary, 'imports'):
            for imported_lib in binary.imports:
                for entry in imported_lib.entries:
                    if any(hint.lower() in entry.name.lower() for hint in signature.import_hints):
                        confidence += 0.2  # 20% weight for imports
                        break
        
        # Entropy check
        entropy = self._calculate_entropy(file_data)
        if entropy >= signature.entropy_threshold:
            confidence += 0.2  # 20% weight for entropy
        
        return min(confidence, 1.0)
    
    def _search_patterns(self, data: bytes, patterns: List[bytes], masks: List[str]) -> List[int]:
        """Search for byte patterns with masks"""
        matches = []
        
        for i, pattern in enumerate(patterns):
            mask = masks[i] if i < len(masks) else 'x' * len(pattern)
            pattern_matches = self._pattern_search_with_mask(data, pattern, mask)
            matches.extend(pattern_matches)
        
        return matches
    
    def _pattern_search_with_mask(self, data: bytes, pattern: bytes, mask: str) -> List[int]:
        """Pattern search with mask support"""
        matches = []
        
        if len(pattern) != len(mask):
            return matches
        
        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if mask[j] == 'x' and data[i + j] != pattern[j]:
                    match = False
                    break
            
            if match:
                matches.append(i)
        
        return matches
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy


class FridaUnpacker:
    """Frida-based dynamic unpacking"""
    
    def __init__(self):
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.memory_dumps: List[bytes] = []
        self.api_calls: List[Dict[str, Any]] = []
    
    def attach_to_process(self, process_name_or_pid: Union[str, int]) -> bool:
        """Attach Frida to target process"""
        try:
            if isinstance(process_name_or_pid, str):
                self.session = frida.attach(process_name_or_pid)
            else:
                self.session = frida.attach(process_name_or_pid)
            
            logger.info(f"Attached to process: {process_name_or_pid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach to process: {e}")
            return False
    
    def inject_unpacking_script(self, protection_type: ProtectionType) -> bool:
        """Inject protection-specific unpacking script"""
        try:
            script_code = self._get_unpacking_script(protection_type)
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            
            logger.info(f"Injected unpacking script for {protection_type.value}")
            return True
            
        except Exception as e:
            logger.error(f"Script injection failed: {e}")
            return False
    
    def _get_unpacking_script(self, protection_type: ProtectionType) -> str:
        """Get protection-specific unpacking script"""
        base_script = """
        var memory_dumps = [];
        var api_calls = [];
        var oep_candidates = [];
        
        // Hook VirtualAlloc family
        var virtualAlloc = Module.findExportByName("kernel32.dll", "VirtualAlloc");
        if (virtualAlloc) {
            Interceptor.attach(virtualAlloc, {
                onEnter: function(args) {
                    this.addr = args[0];
                    this.size = args[1].toInt32();
                    this.type = args[2].toInt32();
                    this.protect = args[3].toInt32();
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        api_calls.push({
                            'function': 'VirtualAlloc',
                            'address': retval.toString(),
                            'size': this.size,
                            'protection': this.protect,
                            'timestamp': Date.now()
                        });
                        
                        // Monitor allocated memory for changes
                        this.monitor_memory(retval, this.size);
                    }
                },
                monitor_memory: function(addr, size) {
                    try {
                        setTimeout(function() {
                            var data = Memory.readByteArray(addr, Math.min(size, 0x1000));
                            memory_dumps.push({
                                'address': addr.toString(),
                                'size': size,
                                'data': data,
                                'timestamp': Date.now()
                            });
                        }, 1000);
                    } catch (e) {
                        console.log("Memory monitoring error: " + e);
                    }
                }
            });
        }
        
        // Hook VirtualProtect
        var virtualProtect = Module.findExportByName("kernel32.dll", "VirtualProtect");
        if (virtualProtect) {
            Interceptor.attach(virtualProtect, {
                onEnter: function(args) {
                    this.addr = args[0];
                    this.size = args[1].toInt32();
                    this.newProtect = args[2].toInt32();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        api_calls.push({
                            'function': 'VirtualProtect',
                            'address': this.addr.toString(),
                            'size': this.size,
                            'protection': this.newProtect,
                            'timestamp': Date.now()
                        });
                        
                        // Check if making memory executable (potential OEP)
                        if ((this.newProtect & 0x20) || (this.newProtect & 0x40)) {
                            oep_candidates.push({
                                'address': this.addr.toString(),
                                'timestamp': Date.now()
                            });
                        }
                    }
                }
            });
        }
        
        // Hook CreateThread
        var createThread = Module.findExportByName("kernel32.dll", "CreateThread");
        if (createThread) {
            Interceptor.attach(createThread, {
                onEnter: function(args) {
                    this.startAddr = args[2];
                },
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        oep_candidates.push({
                            'address': this.startAddr.toString(),
                            'type': 'thread_start',
                            'timestamp': Date.now()
                        });
                    }
                }
            });
        }
        
        // Export data collection functions
        rpc.exports = {
            getDumps: function() {
                return memory_dumps;
            },
            getApiCalls: function() {
                return api_calls;
            },
            getOepCandidates: function() {
                return oep_candidates;
            },
            dumpMemoryRegion: function(addr, size) {
                try {
                    var data = Memory.readByteArray(ptr(addr), size);
                    return data;
                } catch (e) {
                    return null;
                }
            }
        };
        """
        
        # Add protection-specific hooks
        if protection_type == ProtectionType.VMPROTECT:
            base_script += self._get_vmprotect_hooks()
        elif protection_type == ProtectionType.THEMIDA:
            base_script += self._get_themida_hooks()
        elif protection_type == ProtectionType.DENUVO:
            base_script += self._get_denuvo_hooks()
        
        return base_script
    
    def _get_vmprotect_hooks(self) -> str:
        """VMProtect-specific hooks"""
        return """
        // VMProtect-specific hooks
        
        // Hook VMProtect runtime functions
        var vmprotect_begin = Module.findExportByName(null, "VMProtectBegin");
        if (vmprotect_begin) {
            Interceptor.attach(vmprotect_begin, {
                onEnter: function(args) {
                    console.log("VMProtectBegin called");
                    send({'type': 'vmprotect', 'event': 'begin'});
                }
            });
        }
        
        var vmprotect_end = Module.findExportByName(null, "VMProtectEnd");
        if (vmprotect_end) {
            Interceptor.attach(vmprotect_end, {
                onEnter: function(args) {
                    console.log("VMProtectEnd called");
                    send({'type': 'vmprotect', 'event': 'end'});
                }
            });
        }
        
        // Monitor VM handler execution
        var moduleBase = Process.findModuleByName(Process.enumerateModules()[0].name).base;
        var moduleSize = Process.findModuleByName(Process.enumerateModules()[0].name).size;
        
        // Hook common VM handler patterns
        Memory.scan(moduleBase, moduleSize, "68 ?? ?? ?? ?? C3", {
            onMatch: function(address, size) {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        send({
                            'type': 'vmprotect', 
                            'event': 'vm_handler',
                            'address': address.toString()
                        });
                    }
                });
            },
            onError: function(reason) {
                console.log("VM handler scan error: " + reason);
            }
        });
        """
    
    def _get_themida_hooks(self) -> str:
        """Themida-specific hooks"""
        return """
        // Themida-specific hooks
        
        // Hook Themida VM entry points
        var moduleBase = Process.findModuleByName(Process.enumerateModules()[0].name).base;
        var moduleSize = Process.findModuleByName(Process.enumerateModules()[0].name).size;
        
        // Themida VM detection patterns
        Memory.scan(moduleBase, moduleSize, "50 53 51 52 56 57 8B F4", {
            onMatch: function(address, size) {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        send({
                            'type': 'themida',
                            'event': 'vm_entry',
                            'address': address.toString()
                        });
                    }
                });
            },
            onError: function(reason) {
                console.log("Themida scan error: " + reason);
            }
        });
        
        // Hook anti-debug checks
        var isDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
        if (isDebuggerPresent) {
            Interceptor.attach(isDebuggerPresent, {
                onLeave: function(retval) {
                    retval.replace(0); // Always return false
                    send({'type': 'themida', 'event': 'anti_debug_bypass'});
                }
            });
        }
        """
    
    def _get_denuvo_hooks(self) -> str:
        """Denuvo-specific hooks"""
        return """
        // Denuvo-specific hooks
        
        // Hook Steam API calls (common in Denuvo)
        var steamInit = Module.findExportByName("steam_api64.dll", "SteamAPI_Init");
        if (!steamInit) {
            steamInit = Module.findExportByName("steam_api.dll", "SteamAPI_Init");
        }
        
        if (steamInit) {
            Interceptor.attach(steamInit, {
                onEnter: function(args) {
                    send({'type': 'denuvo', 'event': 'steam_init'});
                },
                onLeave: function(retval) {
                    retval.replace(1); // Force success
                }
            });
        }
        
        // Hook hardware ID generation
        var getCPUID = Module.findExportByName("kernel32.dll", "GetCurrentProcessorNumber");
        if (getCPUID) {
            Interceptor.attach(getCPUID, {
                onLeave: function(retval) {
                    send({
                        'type': 'denuvo',
                        'event': 'hwid_check',
                        'processor': retval.toInt32()
                    });
                }
            });
        }
        
        // Monitor code decryption patterns
        var moduleBase = Process.findModuleByName(Process.enumerateModules()[0].name).base;
        var moduleSize = Process.findModuleByName(Process.enumerateModules()[0].name).size;
        
        // Look for Denuvo decryption stubs
        Memory.scan(moduleBase, moduleSize, "48 89 5C 24 08 48 89 6C 24 10", {
            onMatch: function(address, size) {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        send({
                            'type': 'denuvo',
                            'event': 'decrypt_stub',
                            'address': address.toString()
                        });
                    }
                });
            },
            onError: function(reason) {
                console.log("Denuvo scan error: " + reason);
            }
        });
        """
    
    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]):
        """Handle Frida script messages"""
        if message['type'] == 'send':
            payload = message['payload']
            logger.debug(f"Frida message: {payload}")
            
            if 'type' in payload:
                if payload['type'] in ['vmprotect', 'themida', 'denuvo']:
                    self.api_calls.append(payload)
    
    def collect_memory_dumps(self) -> List[bytes]:
        """Collect memory dumps from target process"""
        if not self.script:
            return []
        
        try:
            dumps_data = self.script.exports.get_dumps()
            memory_dumps = []
            
            for dump_info in dumps_data:
                if 'data' in dump_info:
                    memory_dumps.append(bytes(dump_info['data']))
            
            return memory_dumps
            
        except Exception as e:
            logger.error(f"Failed to collect memory dumps: {e}")
            return []
    
    def get_oep_candidates(self) -> List[int]:
        """Get OEP candidates from dynamic analysis"""
        if not self.script:
            return []
        
        try:
            candidates_data = self.script.exports.get_oep_candidates()
            candidates = []
            
            for candidate in candidates_data:
                if 'address' in candidate:
                    candidates.append(int(candidate['address'], 16))
            
            return candidates
            
        except Exception as e:
            logger.error(f"Failed to get OEP candidates: {e}")
            return []
    
    def detach(self):
        """Detach from target process"""
        if self.script:
            self.script.unload()
            self.script = None
        
        if self.session:
            self.session.detach()
            self.session = None


class UniversalUnpacker:
    """Universal unpacker with hybrid dynamic-first approach"""
    
    def __init__(self):
        self.protection_detector = ProtectionDetector()
        self.frida_unpacker = FridaUnpacker()
        self.oep_detector = OEPDetector()
        self.memory_ops = AdvancedMemoryOperations()
    
    def unpack_binary(self, file_path: str, output_path: Optional[str] = None) -> UnpackingResult:
        """Main unpacking interface"""
        start_time = time.time()
        result = UnpackingResult(success=False)
        
        try:
            logger.info(f"Starting unpacking of: {file_path}")
            
            # Detect protection schemes
            detected_protections = self.protection_detector.detect_protection(file_path)
            if not detected_protections:
                result.error_message = "No supported protection detected"
                return result
            
            result.protection_type = detected_protections[0]  # Use primary detection
            logger.info(f"Detected protection: {result.protection_type.value}")
            
            # Start target process in suspended state
            process_info = self._start_suspended_process(file_path)
            if not process_info:
                result.error_message = "Failed to start target process"
                return result
            
            try:
                # Attach Frida
                if not self.frida_unpacker.attach_to_process(process_info['pid']):
                    result.error_message = "Failed to attach Frida"
                    return result
                
                # Inject unpacking script
                if not self.frida_unpacker.inject_unpacking_script(result.protection_type):
                    result.error_message = "Failed to inject unpacking script"
                    return result
                
                # Resume process and monitor
                self._resume_process(process_info['handle'])
                
                # Wait for unpacking to complete
                unpacked_data = self._monitor_unpacking_process(process_info)
                if not unpacked_data:
                    result.error_message = "Unpacking monitoring failed"
                    return result
                
                # Detect OEP
                oep_candidates = self.frida_unpacker.get_oep_candidates()
                if oep_candidates:
                    result.original_entry_point = self.oep_detector.detect_oep(
                        unpacked_data, oep_candidates
                    )
                
                # Collect results
                result.unpacked_data = unpacked_data
                result.unpacked_size = len(unpacked_data)
                result.memory_dumps = self.frida_unpacker.collect_memory_dumps()
                result.api_calls = self.frida_unpacker.api_calls
                result.success = True
                
                # Save unpacked binary
                if output_path:
                    with open(output_path, 'wb') as f:
                        f.write(unpacked_data)
                    logger.info(f"Unpacked binary saved to: {output_path}")
                
            finally:
                # Cleanup
                self.frida_unpacker.detach()
                self._terminate_process(process_info['handle'])
            
        except Exception as e:
            logger.error(f"Unpacking failed: {e}")
            result.error_message = str(e)
        
        finally:
            result.execution_time = time.time() - start_time
        
        return result
    
    def _start_suspended_process(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Start process in suspended state"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Process creation flags
            CREATE_SUSPENDED = 0x00000004
            
            # Startup info structure
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ('cb', wintypes.DWORD),
                    ('lpReserved', wintypes.LPWSTR),
                    ('lpDesktop', wintypes.LPWSTR),
                    ('lpTitle', wintypes.LPWSTR),
                    ('dwX', wintypes.DWORD),
                    ('dwY', wintypes.DWORD),
                    ('dwXSize', wintypes.DWORD),
                    ('dwYSize', wintypes.DWORD),
                    ('dwXCountChars', wintypes.DWORD),
                    ('dwYCountChars', wintypes.DWORD),
                    ('dwFillAttribute', wintypes.DWORD),
                    ('dwFlags', wintypes.DWORD),
                    ('wShowWindow', wintypes.WORD),
                    ('cbReserved2', wintypes.WORD),
                    ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
                    ('hStdInput', wintypes.HANDLE),
                    ('hStdOutput', wintypes.HANDLE),
                    ('hStdError', wintypes.HANDLE),
                ]
            
            # Process information structure
            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ('hProcess', wintypes.HANDLE),
                    ('hThread', wintypes.HANDLE),
                    ('dwProcessId', wintypes.DWORD),
                    ('dwThreadId', wintypes.DWORD),
                ]
            
            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)
            
            process_info = PROCESS_INFORMATION()
            
            # Create suspended process
            success = ctypes.windll.kernel32.CreateProcessW(
                file_path,  # Application name
                None,       # Command line
                None,       # Process security attributes
                None,       # Thread security attributes
                False,      # Inherit handles
                CREATE_SUSPENDED,  # Creation flags
                None,       # Environment
                None,       # Current directory
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            if success:
                return {
                    'handle': process_info.hProcess,
                    'thread_handle': process_info.hThread,
                    'pid': process_info.dwProcessId,
                    'tid': process_info.dwThreadId
                }
            else:
                logger.error("Failed to create suspended process")
                return None
                
        except Exception as e:
            logger.error(f"Process creation failed: {e}")
            return None
    
    def _resume_process(self, thread_handle: int) -> bool:
        """Resume suspended process"""
        try:
            import ctypes
            result = ctypes.windll.kernel32.ResumeThread(thread_handle)
            return result != -1
        except Exception as e:
            logger.error(f"Failed to resume process: {e}")
            return False
    
    def _terminate_process(self, process_handle: int):
        """Terminate process"""
        try:
            import ctypes
            ctypes.windll.kernel32.TerminateProcess(process_handle, 0)
            ctypes.windll.kernel32.CloseHandle(process_handle)
        except Exception as e:
            logger.error(f"Failed to terminate process: {e}")
    
    def _monitor_unpacking_process(self, process_info: Dict[str, Any]) -> Optional[bytes]:
        """Monitor unpacking process and extract unpacked data"""
        try:
            # Give process time to unpack
            time.sleep(5)
            
            # Get memory dumps from Frida
            memory_dumps = self.frida_unpacker.collect_memory_dumps()
            
            if memory_dumps:
                # Find the largest dump (likely the unpacked binary)
                largest_dump = max(memory_dumps, key=len)
                return largest_dump
            
            # Fallback: manual memory scanning
            return self._manual_memory_extraction(process_info['pid'])
            
        except Exception as e:
            logger.error(f"Unpacking monitoring failed: {e}")
            return None
    
    def _manual_memory_extraction(self, pid: int) -> Optional[bytes]:
        """Manual memory extraction as fallback"""
        try:
            import psutil
            
            process = psutil.Process(pid)
            memory_maps = process.memory_maps()
            
            # Look for executable regions
            for mmap in memory_maps:
                if 'x' in mmap.perms:  # Executable
                    # Read memory region
                    data = self.memory_ops.syscall_manager.read_memory(
                        process.as_dict()['pid'], 
                        int(mmap.addr.split('-')[0], 16),
                        mmap.rss
                    )
                    if data and len(data) > 0x1000:  # Reasonable size
                        return data
            
            return None
            
        except Exception as e:
            logger.error(f"Manual memory extraction failed: {e}")
            return None