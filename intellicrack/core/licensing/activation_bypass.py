"""
License & Activation Bypass Engine

Advanced licensing bypass using taint tracking, patch point detection,
and certificate validation bypass for comprehensive license circumvention.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import angr
import frida
import hashlib
import logging
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import capstone
import keystone
import lief
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from ...utils.logger import logger
from ..exploitation.memory_framework import DirectSyscallManager, AdvancedMemoryOperations

logger = logging.getLogger(__name__)


class LicenseType(Enum):
    """License protection types"""
    UNKNOWN = "unknown"
    SERIAL_KEY = "serial_key"
    HARDWARE_ID = "hardware_id"
    ONLINE_ACTIVATION = "online_activation"
    CERTIFICATE = "certificate"
    DONGLE = "dongle"
    TIME_TRIAL = "time_trial"
    FEATURE_UNLOCK = "feature_unlock"
    SUBSCRIPTION = "subscription"


class BypassTechnique(Enum):
    """License bypass techniques"""
    PATCH_VALIDATION = "patch_validation"
    HOOK_APIS = "hook_apis"
    TAINT_TRACKING = "taint_tracking"
    CERTIFICATE_BYPASS = "certificate_bypass"
    NETWORK_INTERCEPTION = "network_interception"
    REGISTRY_MANIPULATION = "registry_manipulation"
    FILE_MODIFICATION = "file_modification"
    MEMORY_PATCHING = "memory_patching"


@dataclass
class LicenseCheck:
    """License validation check point"""
    address: int
    function_name: Optional[str]
    check_type: LicenseType
    bypass_technique: BypassTechnique
    original_bytes: Optional[bytes] = None
    patch_bytes: Optional[bytes] = None
    is_bypassed: bool = False


@dataclass
class TaintedData:
    """Tainted data tracking"""
    source_address: int
    data_value: Any
    taint_id: str
    propagation_path: List[int]
    reached_checks: List[int]


@dataclass
class BypassResult:
    """License bypass result"""
    success: bool
    bypassed_checks: List[LicenseCheck]
    license_type: LicenseType
    bypass_techniques: List[BypassTechnique]
    error_message: Optional[str] = None


class TaintTracker:
    """Advanced taint tracking for license data flow"""
    
    def __init__(self, memory_ops: AdvancedMemoryOperations):
        self.memory_ops = memory_ops
        self.tainted_data: Dict[str, TaintedData] = {}
        self.taint_sources: Set[int] = set()
        self.license_checks: List[int] = []
    
    def initialize_taint_sources(self, process_handle: int, license_keys: List[str]):
        """Initialize taint tracking for license keys"""
        try:
            for i, key in enumerate(license_keys):
                taint_id = f"license_key_{i}"
                
                # Find key in process memory
                key_addresses = self._find_string_in_memory(process_handle, key.encode())
                
                for addr in key_addresses:
                    self.taint_sources.add(addr)
                    self.tainted_data[taint_id] = TaintedData(
                        source_address=addr,
                        data_value=key,
                        taint_id=taint_id,
                        propagation_path=[addr],
                        reached_checks=[]
                    )
                    
                    logger.debug(f"Taint source registered: {key} at 0x{addr:08X}")
            
        except Exception as e:
            logger.error(f"Taint source initialization failed: {e}")
    
    def _find_string_in_memory(self, process_handle: int, data: bytes) -> List[int]:
        """Find string occurrences in process memory"""
        matches = []
        
        try:
            # Scan heap regions for the string
            scan_ranges = self._get_heap_regions(process_handle)
            
            for start_addr, size in scan_ranges:
                found_addresses = self.memory_ops.scan_memory_pattern(
                    process_handle, start_addr, start_addr + size, data
                )
                matches.extend(found_addresses)
            
            return matches
            
        except Exception as e:
            logger.error(f"String search failed: {e}")
            return matches
    
    def _get_heap_regions(self, process_handle: int) -> List[Tuple[int, int]]:
        """Get heap memory regions for scanning"""
        # This would typically enumerate memory regions using VirtualQuery
        # For now, return common heap ranges
        return [
            (0x00400000, 0x00100000),  # Main executable
            (0x10000000, 0x01000000),  # Heap region 1
            (0x20000000, 0x01000000),  # Heap region 2
        ]
    
    def track_propagation(self, from_addr: int, to_addr: int, data_value: Any):
        """Track taint propagation"""
        # Find tainted data that might be propagating
        for taint_id, taint_data in self.tainted_data.items():
            if from_addr in taint_data.propagation_path:
                # Update propagation path
                if to_addr not in taint_data.propagation_path:
                    taint_data.propagation_path.append(to_addr)
                    logger.debug(f"Taint propagation: {taint_id} -> 0x{to_addr:08X}")
    
    def check_license_validation(self, check_addr: int) -> List[str]:
        """Check if address is reached by tainted data"""
        reached_taints = []
        
        for taint_id, taint_data in self.tainted_data.items():
            if check_addr in taint_data.propagation_path:
                taint_data.reached_checks.append(check_addr)
                reached_taints.append(taint_id)
                logger.info(f"License check at 0x{check_addr:08X} reached by taint {taint_id}")
        
        return reached_taints


class LicenseDetector:
    """License protection scheme detection"""
    
    def __init__(self):
        self.license_patterns = self._initialize_patterns()
    
    def _initialize_patterns(self) -> Dict[LicenseType, Dict[str, Any]]:
        """Initialize license detection patterns"""
        return {
            LicenseType.SERIAL_KEY: {
                'strings': [
                    b'serial', b'license', b'registration', b'activation',
                    b'product key', b'unlock code', b'license key'
                ],
                'api_calls': [
                    'RegQueryValueEx', 'RegSetValueEx', 'CryptDecrypt',
                    'CryptHashData', 'CheckLicenseKey'
                ],
                'patterns': [
                    b'\x8B\x45\x08\x50\xE8',  # mov eax, [ebp+8]; push eax; call
                    b'\x83\xF8\x00\x74',      # cmp eax, 0; jz
                ]
            },
            
            LicenseType.HARDWARE_ID: {
                'strings': [
                    b'hardware', b'machine id', b'computer id', b'fingerprint',
                    b'system info', b'hardware hash'
                ],
                'api_calls': [
                    'GetVolumeInformation', 'GetAdaptersInfo', 'GetSystemInfo',
                    'RegQueryValueEx', 'WMI'
                ],
                'patterns': [
                    b'\x68\x00\x00\x00\x00\xFF\x15',  # push 0; call [import]
                ]
            },
            
            LicenseType.ONLINE_ACTIVATION: {
                'strings': [
                    b'activation', b'server', b'online', b'internet',
                    b'http', b'https', b'validate'
                ],
                'api_calls': [
                    'InternetOpen', 'HttpOpenRequest', 'HttpSendRequest',
                    'WinHttpOpen', 'WSAStartup'
                ],
                'patterns': [
                    b'\x6A\x00\x6A\x00\x6A\x00\x6A\x00\xFF\x15',  # HTTP call pattern
                ]
            },
            
            LicenseType.CERTIFICATE: {
                'strings': [
                    b'certificate', b'X.509', b'public key', b'signature',
                    b'RSA', b'DSA', b'verify'
                ],
                'api_calls': [
                    'CryptVerifySignature', 'CertVerifySubject', 'CryptImportKey',
                    'CryptDecrypt', 'CertCreateCertificateContext'
                ],
                'patterns': [
                    b'\x30\x82',  # ASN.1 certificate beginning
                ]
            },
            
            LicenseType.TIME_TRIAL: {
                'strings': [
                    b'trial', b'expire', b'days left', b'evaluation',
                    b'demo', b'time limit'
                ],
                'api_calls': [
                    'GetSystemTime', 'GetFileTime', 'CompareFileTime',
                    'SystemTimeToFileTime', 'RegQueryValueEx'
                ],
                'patterns': [
                    b'\xFF\x15\x00\x00\x00\x00\x85\xC0',  # call [GetSystemTime]; test eax, eax
                ]
            }
        }
    
    def detect_license_scheme(self, binary_path: str) -> List[LicenseType]:
        """Detect license protection schemes"""
        detected_schemes = []
        
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Check each license type
            for license_type, patterns in self.license_patterns.items():
                confidence = self._calculate_detection_confidence(binary_data, patterns)
                
                if confidence > 0.6:  # 60% confidence threshold
                    detected_schemes.append(license_type)
                    logger.info(f"Detected {license_type.value} protection (confidence: {confidence:.2%})")
            
            return detected_schemes
            
        except Exception as e:
            logger.error(f"License scheme detection failed: {e}")
            return detected_schemes
    
    def _calculate_detection_confidence(self, data: bytes, patterns: Dict[str, Any]) -> float:
        """Calculate detection confidence"""
        confidence = 0.0
        total_weight = 3  # strings, api_calls, patterns
        
        # String pattern matching
        string_matches = 0
        for string_pattern in patterns.get('strings', []):
            if string_pattern in data:
                string_matches += 1
        
        if string_matches > 0:
            confidence += 0.4  # 40% weight for strings
        
        # API call pattern matching
        api_matches = 0
        for api_name in patterns.get('api_calls', []):
            if api_name.encode() in data:
                api_matches += 1
        
        if api_matches > 0:
            confidence += 0.3  # 30% weight for APIs
        
        # Code pattern matching
        code_matches = 0
        for code_pattern in patterns.get('patterns', []):
            if code_pattern in data:
                code_matches += 1
        
        if code_matches > 0:
            confidence += 0.3  # 30% weight for code patterns
        
        return confidence


class PatchPointDetector:
    """Automated patch point detection using angr"""
    
    def __init__(self):
        self.project: Optional[angr.Project] = None
        self.cfg: Optional[angr.knowledge_plugins.CFGFast] = None
    
    def detect_patch_points(self, binary_path: str, license_checks: List[int]) -> List[LicenseCheck]:
        """Detect optimal patch points for license bypasses"""
        try:
            logger.info("Detecting patch points using symbolic execution")
            
            # Load binary in angr
            self.project = angr.Project(binary_path, auto_load_libs=False)
            self.cfg = self.project.analyses.CFGFast()
            
            patch_points = []
            
            for check_addr in license_checks:
                patch_point = self._analyze_license_check(check_addr)
                if patch_point:
                    patch_points.append(patch_point)
            
            return patch_points
            
        except Exception as e:
            logger.error(f"Patch point detection failed: {e}")
            return []
    
    def _analyze_license_check(self, check_addr: int) -> Optional[LicenseCheck]:
        """Analyze a specific license check for bypass opportunities"""
        try:
            # Find function containing this address
            function = self.project.kb.functions.floor_func(check_addr)
            if not function:
                return None
            
            # Analyze function to understand license check logic
            state = self.project.factory.entry_state(addr=function.addr)
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore paths to find conditional branches
            simgr.explore(find=check_addr, num_find=1)
            
            if simgr.found:
                found_state = simgr.found[0]
                
                # Analyze the check logic
                bypass_info = self._generate_bypass_patch(found_state, check_addr)
                
                if bypass_info:
                    return LicenseCheck(
                        address=check_addr,
                        function_name=function.name,
                        check_type=LicenseType.UNKNOWN,  # Would be determined by context
                        bypass_technique=BypassTechnique.PATCH_VALIDATION,
                        original_bytes=bypass_info['original'],
                        patch_bytes=bypass_info['patch']
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"License check analysis failed: {e}")
            return None
    
    def _generate_bypass_patch(self, state: angr.SimState, check_addr: int) -> Optional[Dict[str, bytes]]:
        """Generate bypass patch for license check"""
        try:
            # Read instruction at check address
            insn_bytes = state.memory.load(check_addr, 16)  # Read up to 16 bytes
            
            # Disassemble instruction
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            instructions = list(cs.disasm(insn_bytes.concrete, check_addr))
            
            if not instructions:
                return None
            
            insn = instructions[0]
            
            # Generate appropriate bypass based on instruction type
            if insn.mnemonic.startswith('j'):  # Conditional jump
                # Patch to unconditional jump or NOP
                if 'nz' in insn.mnemonic or 'ne' in insn.mnemonic:
                    # Convert JNZ to JMP (always take the branch)
                    patch = self._generate_jmp_patch(insn)
                else:
                    # Convert JZ to NOP (never take the branch)
                    patch = b'\x90' * insn.size
                
                return {
                    'original': insn_bytes.concrete[:insn.size],
                    'patch': patch
                }
            
            elif insn.mnemonic == 'test' or insn.mnemonic == 'cmp':
                # Patch comparison to always succeed
                # Replace with XOR reg, reg to set ZF
                patch = self._generate_success_patch(insn)
                
                return {
                    'original': insn_bytes.concrete[:insn.size],
                    'patch': patch
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Bypass patch generation failed: {e}")
            return None
    
    def _generate_jmp_patch(self, insn: Any) -> bytes:
        """Generate unconditional jump patch"""
        try:
            # Convert conditional jump to unconditional jump
            if insn.size == 2:  # Short jump
                return b'\xEB' + insn.bytes[1:2]  # JMP short
            elif insn.size >= 5:  # Near jump
                return b'\xE9' + insn.bytes[1:5]  # JMP near
            else:
                return b'\x90' * insn.size  # NOP as fallback
                
        except Exception:
            return b'\x90' * insn.size
    
    def _generate_success_patch(self, insn: Any) -> bytes:
        """Generate patch to make comparison always succeed"""
        try:
            # XOR EAX, EAX (sets ZF=1)
            if insn.size >= 2:
                return b'\x33\xC0' + b'\x90' * (insn.size - 2)
            else:
                return b'\x90' * insn.size
                
        except Exception:
            return b'\x90' * insn.size


class CertificateBypass:
    """Certificate validation bypass"""
    
    def __init__(self, memory_ops: AdvancedMemoryOperations):
        self.memory_ops = memory_ops
    
    def bypass_certificate_validation(self, process_handle: int) -> bool:
        """Bypass certificate validation mechanisms"""
        try:
            # Hook certificate validation APIs
            hooked_apis = self._hook_cert_apis(process_handle)
            
            if hooked_apis:
                logger.info(f"Certificate validation bypass installed ({len(hooked_apis)} APIs hooked)")
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Certificate bypass failed: {e}")
            return False
    
    def _hook_cert_apis(self, process_handle: int) -> List[str]:
        """Hook certificate validation APIs"""
        hooked_apis = []
        
        cert_apis = [
            ('crypt32.dll', 'CryptVerifySignature'),
            ('crypt32.dll', 'CertVerifySubjectCertificateContext'),
            ('crypt32.dll', 'CryptDecrypt'),
            ('advapi32.dll', 'CryptVerifySignatureA'),
            ('advapi32.dll', 'CryptVerifySignatureW'),
        ]
        
        for dll_name, api_name in cert_apis:
            if self._install_api_hook(process_handle, dll_name, api_name):
                hooked_apis.append(f"{dll_name}!{api_name}")
        
        return hooked_apis
    
    def _install_api_hook(self, process_handle: int, dll_name: str, api_name: str) -> bool:
        """Install hook for certificate API"""
        try:
            # Get API address (simplified - would need proper resolution)
            api_address = self._get_api_address(dll_name, api_name)
            if not api_address:
                return False
            
            # Generate hook code to always return success
            hook_code = self._generate_cert_hook_code(api_name)
            
            # Install hook
            return self.memory_ops.syscall_manager.write_memory(
                process_handle, api_address, hook_code
            )
            
        except Exception as e:
            logger.error(f"API hook installation failed: {e}")
            return False
    
    def _get_api_address(self, dll_name: str, api_name: str) -> Optional[int]:
        """Get API address (simplified implementation)"""
        # This would need proper implementation to resolve APIs in target process
        return None
    
    def _generate_cert_hook_code(self, api_name: str) -> bytes:
        """Generate hook code for certificate APIs"""
        if 'Verify' in api_name:
            # Return TRUE (success)
            return b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret
        elif 'Decrypt' in api_name:
            # Return ERROR_SUCCESS
            return b'\xB8\x00\x00\x00\x00\xC3'  # mov eax, 0; ret
        else:
            # Generic success
            return b'\xB8\x01\x00\x00\x00\xC3'  # mov eax, 1; ret


class ActivationBypass:
    """Main license and activation bypass engine"""
    
    def __init__(self):
        self.memory_ops = AdvancedMemoryOperations()
        self.license_detector = LicenseDetector()
        self.taint_tracker = TaintTracker(self.memory_ops)
        self.patch_detector = PatchPointDetector()
        self.cert_bypass = CertificateBypass(self.memory_ops)
        
        self.active_bypasses: Dict[int, List[LicenseCheck]] = {}
    
    def bypass_license_protection(self, binary_path: str, target_pid: Optional[int] = None,
                                 license_keys: Optional[List[str]] = None) -> BypassResult:
        """Comprehensive license protection bypass"""
        try:
            logger.info(f"Starting license bypass for: {binary_path}")
            
            # Detect license schemes
            detected_schemes = self.license_detector.detect_license_scheme(binary_path)
            if not detected_schemes:
                return BypassResult(
                    success=False,
                    bypassed_checks=[],
                    license_type=LicenseType.UNKNOWN,
                    bypass_techniques=[],
                    error_message="No license protection detected"
                )
            
            primary_scheme = detected_schemes[0]
            logger.info(f"Primary license scheme: {primary_scheme.value}")
            
            bypassed_checks = []
            bypass_techniques = []
            
            if target_pid:
                # Dynamic bypass using live process
                process_result = self._bypass_live_process(
                    target_pid, primary_scheme, license_keys or []
                )
                bypassed_checks.extend(process_result['checks'])
                bypass_techniques.extend(process_result['techniques'])
            else:
                # Static analysis and patch generation
                static_result = self._generate_static_patches(binary_path, primary_scheme)
                bypassed_checks.extend(static_result['checks'])
                bypass_techniques.extend(static_result['techniques'])
            
            success = len(bypassed_checks) > 0
            
            return BypassResult(
                success=success,
                bypassed_checks=bypassed_checks,
                license_type=primary_scheme,
                bypass_techniques=bypass_techniques,
                error_message=None if success else "No bypass opportunities found"
            )
            
        except Exception as e:
            logger.error(f"License bypass failed: {e}")
            return BypassResult(
                success=False,
                bypassed_checks=[],
                license_type=LicenseType.UNKNOWN,
                bypass_techniques=[],
                error_message=str(e)
            )
    
    def _bypass_live_process(self, pid: int, license_type: LicenseType, 
                           license_keys: List[str]) -> Dict[str, Any]:
        """Bypass license protection in live process"""
        try:
            # Get process handle
            PROCESS_ALL_ACCESS = 0x1F0FFF
            import ctypes
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            
            if not process_handle:
                return {'checks': [], 'techniques': []}
            
            try:
                bypassed_checks = []
                techniques = []
                
                # Initialize taint tracking if license keys provided
                if license_keys:
                    self.taint_tracker.initialize_taint_sources(process_handle, license_keys)
                    techniques.append(BypassTechnique.TAINT_TRACKING)
                
                # Apply scheme-specific bypasses
                if license_type == LicenseType.CERTIFICATE:
                    if self.cert_bypass.bypass_certificate_validation(process_handle):
                        techniques.append(BypassTechnique.CERTIFICATE_BYPASS)
                
                # Memory patching for common license checks
                license_checks = self._find_license_checks_in_memory(process_handle, license_type)
                
                for check_addr in license_checks:
                    patch_result = self._apply_memory_patch(process_handle, check_addr)
                    if patch_result:
                        bypassed_checks.append(patch_result)
                        techniques.append(BypassTechnique.MEMORY_PATCHING)
                
                self.active_bypasses[pid] = bypassed_checks
                
                return {'checks': bypassed_checks, 'techniques': techniques}
                
            finally:
                ctypes.windll.kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            logger.error(f"Live process bypass failed: {e}")
            return {'checks': [], 'techniques': []}
    
    def _generate_static_patches(self, binary_path: str, 
                                license_type: LicenseType) -> Dict[str, Any]:
        """Generate static patches for license bypass"""
        try:
            # Use angr to find license check functions
            potential_checks = self._find_license_check_functions(binary_path, license_type)
            
            # Generate patches using PatchPointDetector
            patch_points = self.patch_detector.detect_patch_points(binary_path, potential_checks)
            
            techniques = [BypassTechnique.PATCH_VALIDATION] if patch_points else []
            
            return {'checks': patch_points, 'techniques': techniques}
            
        except Exception as e:
            logger.error(f"Static patch generation failed: {e}")
            return {'checks': [], 'techniques': []}
    
    def _find_license_checks_in_memory(self, process_handle: int, 
                                     license_type: LicenseType) -> List[int]:
        """Find license check addresses in process memory"""
        check_addresses = []
        
        try:
            # Scan for license check patterns based on type
            if license_type == LicenseType.SERIAL_KEY:
                # Look for string comparison patterns
                patterns = [
                    b'\x83\xF8\x00\x74',  # cmp eax, 0; jz
                    b'\x85\xC0\x74',      # test eax, eax; jz
                ]
            elif license_type == LicenseType.TIME_TRIAL:
                # Look for time comparison patterns
                patterns = [
                    b'\xFF\x15\x00\x00\x00\x00\x85\xC0',  # call [GetSystemTime]; test eax, eax
                ]
            else:
                # Generic patterns
                patterns = [
                    b'\x83\xF8\x00\x74',  # cmp eax, 0; jz
                ]
            
            # Scan executable regions
            for pattern in patterns:
                matches = self.memory_ops.scan_memory_pattern(
                    process_handle, 0x400000, 0x500000, pattern  # Main executable region
                )
                check_addresses.extend(matches)
            
            return check_addresses
            
        except Exception as e:
            logger.error(f"License check scanning failed: {e}")
            return check_addresses
    
    def _find_license_check_functions(self, binary_path: str, 
                                    license_type: LicenseType) -> List[int]:
        """Find license check functions using static analysis"""
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Use simple pattern matching for now
            check_addresses = []
            
            # Define patterns based on license type
            if license_type == LicenseType.SERIAL_KEY:
                patterns = [b'serial', b'license', b'registration']
            elif license_type == LicenseType.TIME_TRIAL:
                patterns = [b'trial', b'expire', b'demo']
            else:
                patterns = [b'license', b'activation']
            
            # Find string references and nearby code
            for pattern in patterns:
                offset = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break
                    
                    # Look for code references to this string
                    # (Simplified - would need proper cross-reference analysis)
                    check_addresses.append(pos)
                    offset = pos + 1
            
            return check_addresses
            
        except Exception as e:
            logger.error(f"License function detection failed: {e}")
            return []
    
    def _apply_memory_patch(self, process_handle: int, check_addr: int) -> Optional[LicenseCheck]:
        """Apply memory patch to bypass license check"""
        try:
            # Read original instruction
            original_bytes = self.memory_ops.syscall_manager.read_memory(
                process_handle, check_addr, 16
            )
            if not original_bytes:
                return None
            
            # Generate bypass patch (simplified)
            if original_bytes[0] == 0x74:  # JZ instruction
                patch_bytes = b'\xEB' + original_bytes[1:2]  # Convert to JMP
            elif original_bytes[:2] == b'\x83\xF8':  # CMP EAX, immediate
                patch_bytes = b'\x33\xC0' + b'\x90' * (len(original_bytes) - 2)  # XOR EAX, EAX
            else:
                patch_bytes = b'\x90' * min(len(original_bytes), 8)  # NOP
            
            # Apply patch
            if self.memory_ops.syscall_manager.write_memory(
                process_handle, check_addr, patch_bytes[:8]
            ):
                return LicenseCheck(
                    address=check_addr,
                    function_name=None,
                    check_type=LicenseType.UNKNOWN,
                    bypass_technique=BypassTechnique.MEMORY_PATCHING,
                    original_bytes=original_bytes[:8],
                    patch_bytes=patch_bytes[:8],
                    is_bypassed=True
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Memory patch application failed: {e}")
            return None
    
    def restore_original_code(self, pid: int) -> bool:
        """Restore original code for all bypasses"""
        try:
            if pid not in self.active_bypasses:
                return True
            
            # Get process handle
            PROCESS_ALL_ACCESS = 0x1F0FFF
            import ctypes
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            
            if not process_handle:
                return False
            
            try:
                success = True
                
                for bypass in self.active_bypasses[pid]:
                    if bypass.original_bytes:
                        if not self.memory_ops.syscall_manager.write_memory(
                            process_handle, bypass.address, bypass.original_bytes
                        ):
                            success = False
                
                if success:
                    del self.active_bypasses[pid]
                
                return success
                
            finally:
                ctypes.windll.kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            logger.error(f"Code restoration failed: {e}")
            return False
    
    def get_bypass_status(self, pid: int) -> Dict[str, Any]:
        """Get current bypass status for process"""
        if pid not in self.active_bypasses:
            return {'active': False, 'bypasses': []}
        
        bypasses = self.active_bypasses[pid]
        
        return {
            'active': True,
            'bypass_count': len(bypasses),
            'bypasses': [
                {
                    'address': f"0x{bypass.address:08X}",
                    'technique': bypass.bypass_technique.value,
                    'is_bypassed': bypass.is_bypassed
                }
                for bypass in bypasses
            ]
        }