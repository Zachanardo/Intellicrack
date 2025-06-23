#!/usr/bin/env python3
"""
Real Licensing Patterns Extractor

Extracts actual licensing logic patterns from real binaries.
Supports all major licensing schemes and protection mechanisms.
"""

import os
import re
import struct
import hashlib
import logging
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import numpy as np

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("Warning: pefile not available. Install with: pip install pefile")

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False
    print("Warning: r2pipe not available. Install with: pip install r2pipe")

logger = logging.getLogger(__name__)


class LicensingPatternsExtractor:
    """Extract real licensing patterns from binaries"""
    
    def __init__(self):
        # Comprehensive licensing-related API patterns
        self.licensing_apis = {
            # Registry operations for license storage
            'registry': [
                'RegOpenKeyEx', 'RegQueryValueEx', 'RegSetValueEx', 'RegCreateKeyEx',
                'RegDeleteValue', 'RegEnumKeyEx', 'RegCloseKey', 'RegDeleteKey',
                'SHGetValue', 'SHSetValue', 'RegGetValue', 'RegSetKeyValue'
            ],
            # Cryptographic operations for license validation
            'crypto': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'CryptCreateHash',
                'CryptAcquireContext', 'CryptGenKey', 'CryptExportKey', 'CryptImportKey',
                'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey',
                'BCryptHash', 'BCryptSignHash', 'BCryptVerifySignature'
            ],
            # Network operations for online validation
            'network': [
                'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'HttpOpenRequest',
                'InternetReadFile', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
                'URLDownloadToFile', 'socket', 'connect', 'send', 'recv', 'WSAStartup',
                'getaddrinfo', 'gethostbyname'
            ],
            # Time operations for trial/expiration
            'time': [
                'GetSystemTime', 'GetLocalTime', 'SystemTimeToFileTime', 'FileTimeToSystemTime',
                'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter', 'time',
                'localtime', 'mktime', 'difftime', 'GetSystemTimeAsFileTime'
            ],
            # Hardware ID for machine locking
            'hardware': [
                'GetVolumeInformation', 'GetComputerName', 'GetUserName', 'GetSystemInfo',
                'GetNativeSystemInfo', 'GetLogicalDriveStrings', 'GetDriveType',
                'DeviceIoControl', 'GetAdaptersInfo', 'GetAdaptersAddresses',
                'GetCurrentHwProfile', 'WMI', 'UUID', 'CPUID'
            ],
            # Process/Anti-tampering operations
            'protection': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
                'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
                'OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory', 'VirtualProtect',
                'GetModuleHandle', 'GetProcAddress', 'LoadLibrary'
            ],
            # File operations for license files
            'file': [
                'CreateFile', 'ReadFile', 'WriteFile', 'GetFileAttributes', 'SetFileAttributes',
                'FindFirstFile', 'FindNextFile', 'DeleteFile', 'MoveFile', 'CopyFile',
                'GetModuleFileName', 'GetCurrentDirectory', 'SetCurrentDirectory'
            ]
        }
        
        # Licensing string patterns with categories
        self.licensing_strings = {
            'license_files': [
                r'\.lic\b', r'\.key\b', r'\.dat\b', r'license\.(txt|xml|json|dat|key|lic)',
                r'serial\.(txt|dat|key)', r'activation\.(dat|key|xml)', r'registration\.dat',
                r'keyfile\.', r'\.license\b', r'\.activation\b'
            ],
            'license_keys': [
                r'[A-Z0-9]{4,6}-[A-Z0-9]{4,6}-[A-Z0-9]{4,6}', # XXXX-XXXX-XXXX format
                r'[A-Z0-9]{25}', # 25-char product keys
                r'[A-F0-9]{32}', # MD5 hash format
                r'[A-F0-9]{40}', # SHA1 hash format
                r'[A-F0-9]{64}', # SHA256 hash format
                r'[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}' # 5x5 format
            ],
            'license_text': [
                r'licen[sc]e', r'serial', r'product\s*key', r'activation\s*code',
                r'registration\s*code', r'unlock\s*code', r'keyfile', r'hardware\s*id',
                r'machine\s*code', r'computer\s*id', r'node\s*locked', r'floating\s*licen[sc]e',
                r'trial', r'evaluation', r'demo', r'expire', r'valid\s*until', r'days\s*remaining',
                r'grace\s*period', r'subscription', r'renewal'
            ],
            'registry_keys': [
                r'SOFTWARE\\[^\\]+\\License', r'SOFTWARE\\[^\\]+\\Registration',
                r'SOFTWARE\\[^\\]+\\Activation', r'HKEY_LOCAL_MACHINE\\SOFTWARE\\[^\\]+\\License',
                r'HKEY_CURRENT_USER\\SOFTWARE\\[^\\]+\\License', r'Classes\\Licenses',
                r'SOFTWARE\\RegisteredApplications'
            ],
            'urls': [
                r'https?://[^/]+/licen[sc]e', r'https?://[^/]+/activate',
                r'https?://[^/]+/validate', r'https?://[^/]+/verify',
                r'https?://[^/]+/register', r'https?://[^/]+/auth'
            ],
            'crypto': [
                r'RSA', r'AES', r'DES', r'3DES', r'SHA\d+', r'MD5',
                r'HMAC', r'private\s*key', r'public\s*key', r'signature',
                r'certificate', r'X\.509', r'PKCS'
            ]
        }
        
        # Known licensing schemes and their characteristics
        self.licensing_schemes = {
            'flexlm': {
                'strings': ['FLEXlm', 'lmgrd', 'FEATURE', 'INCREMENT', 'VENDOR_STRING'],
                'files': ['license.dat', 'license.lic', '.flexlmrc'],
                'apis': ['gethostid', 'ether_hostid']
            },
            'sentinel': {
                'strings': ['Sentinel', 'HASP', 'SuperPro', 'SafeNet'],
                'files': ['hasp_rt.exe', 'hasplms.exe'],
                'apis': ['hasp_login', 'hasp_encrypt', 'hasp_decrypt']
            },
            'codemeter': {
                'strings': ['CodeMeter', 'CmDongle', 'WIBU', 'CmActLicense'],
                'files': ['CodeMeter.exe', 'WibuCm32.dll'],
                'apis': ['CmAccess', 'CmCrypt', 'CmGetLicenseInfo']
            },
            'softwarepassport': {
                'strings': ['Armadillo', 'Software Passport', 'Silicon Realms'],
                'files': ['ArmAccess.dll'],
                'apis': ['ArmAccess', 'CheckProtection']
            },
            'winlicense': {
                'strings': ['WinLicense', 'Themida', 'SecureEngine'],
                'files': ['SecureEngine.dll'],
                'apis': ['SECheckProtection', 'SECheckVirtualPC']
            },
            'asprotect': {
                'strings': ['ASProtect', 'ASPack'],
                'files': [],
                'apis': ['ASProtectIsRegistered', 'ASProtectDecrypt']
            },
            'custom': {
                'strings': ['IsLicensed', 'CheckLicense', 'ValidateLicense', 'VerifyKey'],
                'files': [],
                'apis': []
            }
        }
    
    def extract_features(self, binary_path: str) -> Dict[str, float]:
        """
        Extract comprehensive licensing-related features from a binary
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Dictionary of feature_name -> value
        """
        features = {}
        
        try:
            # Basic file analysis
            file_features = self._extract_file_features(binary_path)
            features.update(file_features)
            
            # PE analysis for Windows binaries
            if PEFILE_AVAILABLE:
                pe_features = self._extract_pe_features(binary_path)
                features.update(pe_features)
            
            # String analysis
            string_features = self._extract_string_features(binary_path)
            features.update(string_features)
            
            # Code analysis with radare2
            if R2PIPE_AVAILABLE:
                code_features = self._extract_code_features(binary_path)
                features.update(code_features)
            
            # Licensing scheme detection
            scheme_features = self._detect_licensing_schemes(binary_path)
            features.update(scheme_features)
            
            # Calculate composite scores
            features['licensing_score'] = self._calculate_licensing_score(features)
            features['protection_level'] = self._calculate_protection_level(features)
            
        except Exception as e:
            logger.error(f"Error extracting features from {binary_path}: {e}")
            # Return minimal feature set on error
            features = self._get_default_features()
        
        return features
    
    def _extract_file_features(self, binary_path: str) -> Dict[str, float]:
        """Extract basic file-level features"""
        features = {}
        
        try:
            file_size = os.path.getsize(binary_path)
            features['file_size'] = float(file_size)
            
            # Read file for analysis
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Calculate entropy
            features['entropy'] = self._calculate_entropy(data)
            
            # Check for common packers/protectors
            features['is_packed'] = float(features['entropy'] > 7.0)
            
            # File type detection
            if data[:2] == b'MZ':
                features['is_pe'] = 1.0
                features['is_elf'] = 0.0
            elif data[:4] == b'\x7fELF':
                features['is_pe'] = 0.0
                features['is_elf'] = 1.0
            else:
                features['is_pe'] = 0.0
                features['is_elf'] = 0.0
            
            # Signature patterns
            features['has_digital_signature'] = float(b'<signature>' in data or b'X509' in data)
            
        except Exception as e:
            logger.debug(f"File feature extraction error: {e}")
            features.update({
                'file_size': 0.0,
                'entropy': 5.0,
                'is_packed': 0.0,
                'is_pe': 0.0,
                'is_elf': 0.0,
                'has_digital_signature': 0.0
            })
        
        return features
    
    def _extract_pe_features(self, binary_path: str) -> Dict[str, float]:
        """Extract PE-specific licensing features"""
        features = {}
        
        if not PEFILE_AVAILABLE:
            return features
        
        try:
            pe = pefile.PE(binary_path)
            
            # Import analysis
            import_counts = defaultdict(int)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            # Categorize imports
                            for category, api_list in self.licensing_apis.items():
                                if any(api in func_name for api in api_list):
                                    import_counts[category] += 1
            
            # Set import features
            for category in self.licensing_apis:
                features[f'imports_{category}_count'] = float(import_counts.get(category, 0))
            
            # Resource analysis
            features['has_resources'] = float(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
            if features['has_resources']:
                try:
                    resource_dir = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
                    if resource_dir and hasattr(resource_dir, 'entries'):
                        features['resource_count'] = float(len(resource_dir.entries))
                    else:
                        features['resource_count'] = 0.0
                except AttributeError:
                    features['resource_count'] = 0.0
            else:
                features['resource_count'] = 0.0
            
            # Section analysis
            features['section_count'] = float(len(pe.sections))
            executable_sections = 0
            writable_sections = 0
            high_entropy_sections = 0
            
            for section in pe.sections:
                characteristics = section.Characteristics
                if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    executable_sections += 1
                if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                    writable_sections += 1
                
                # Calculate section entropy
                section_data = section.get_data()
                if len(section_data) > 0:
                    section_entropy = self._calculate_entropy(section_data)
                    if section_entropy > 7.0:
                        high_entropy_sections += 1
            
            features['executable_sections'] = float(executable_sections)
            features['writable_sections'] = float(writable_sections)
            features['high_entropy_sections'] = float(high_entropy_sections)
            
            # TLS callbacks (often used by protectors)
            features['has_tls'] = float(hasattr(pe, 'DIRECTORY_ENTRY_TLS'))
            
            # Export analysis (DLLs)
            features['is_dll'] = float(pe.is_dll())
            features['export_count'] = 0.0
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['export_count'] = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
            
            pe.close()
            
        except Exception as e:
            logger.debug(f"PE feature extraction error: {e}")
            # Set default PE features
            for category in self.licensing_apis:
                features[f'imports_{category}_count'] = 0.0
            features.update({
                'has_resources': 0.0,
                'resource_count': 0.0,
                'section_count': 4.0,
                'executable_sections': 1.0,
                'writable_sections': 1.0,
                'high_entropy_sections': 0.0,
                'has_tls': 0.0,
                'is_dll': 0.0,
                'export_count': 0.0
            })
        
        return features
    
    def _extract_string_features(self, binary_path: str) -> Dict[str, float]:
        """Extract licensing-related string features"""
        features = {}
        
        try:
            # Read binary data
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Convert to string for pattern matching
            try:
                text_data = data.decode('utf-8', errors='ignore')
            except:
                text_data = data.decode('latin-1', errors='ignore')
            
            # Extract ASCII strings
            ascii_strings = re.findall(b'[\x20-\x7E]{4,}', data)
            ascii_text = b' '.join(ascii_strings).decode('utf-8', errors='ignore')
            
            # Extract Unicode strings
            unicode_strings = re.findall(b'(?:[\x20-\x7E]\x00){4,}', data)
            unicode_text = b' '.join(unicode_strings).decode('utf-16le', errors='ignore')
            
            # Combine all text
            all_text = text_data + ' ' + ascii_text + ' ' + unicode_text
            
            # Count string patterns
            for category, patterns in self.licensing_strings.items():
                count = 0
                for pattern in patterns:
                    matches = re.findall(pattern, all_text, re.IGNORECASE)
                    count += len(matches)
                features[f'strings_{category}_count'] = float(count)
            
            # Specific license key patterns
            features['has_license_key_pattern'] = float(
                bool(re.search(r'[A-Z0-9]{4,6}-[A-Z0-9]{4,6}-[A-Z0-9]{4,6}', all_text))
            )
            
            # URL patterns
            features['license_url_count'] = float(
                len(re.findall(r'https?://[^\s]+(?:licen[sc]e|activate|validate|register)', all_text, re.IGNORECASE))
            )
            
            # Email patterns (support/licensing contacts)
            features['has_support_email'] = float(
                bool(re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', all_text))
            )
            
            # Copyright and license text
            features['has_copyright'] = float(bool(re.search(r'copyright|©|\(c\)', all_text, re.IGNORECASE)))
            features['has_eula'] = float(bool(re.search(r'end user license|eula|license agreement', all_text, re.IGNORECASE)))
            
        except Exception as e:
            logger.debug(f"String feature extraction error: {e}")
            # Set default string features
            for category in self.licensing_strings:
                features[f'strings_{category}_count'] = 0.0
            features.update({
                'has_license_key_pattern': 0.0,
                'license_url_count': 0.0,
                'has_support_email': 0.0,
                'has_copyright': 0.0,
                'has_eula': 0.0
            })
        
        return features
    
    def _extract_code_features(self, binary_path: str) -> Dict[str, float]:
        """Extract code-level licensing features using radare2"""
        features = {}
        
        if not R2PIPE_AVAILABLE:
            return features
        
        try:
            # Open binary in radare2
            r2 = r2pipe.open(binary_path, flags=['-2'])  # -2 for faster analysis
            
            # Analyze binary
            r2.cmd('aaa')  # Full analysis
            
            # Get functions
            functions = r2.cmdj('aflj') or []
            features['function_count'] = float(len(functions))
            
            # Look for licensing-related function names
            licensing_functions = 0
            crypto_functions = 0
            time_functions = 0
            
            for func in functions:
                func_name = func.get('name', '').lower()
                
                # Check for licensing patterns
                if any(pattern in func_name for pattern in ['license', 'serial', 'key', 'activate', 'register', 'validate']):
                    licensing_functions += 1
                
                # Check for crypto patterns
                if any(pattern in func_name for pattern in ['crypt', 'hash', 'aes', 'rsa', 'sha', 'md5']):
                    crypto_functions += 1
                
                # Check for time patterns
                if any(pattern in func_name for pattern in ['time', 'date', 'expire', 'trial']):
                    time_functions += 1
            
            features['licensing_functions'] = float(licensing_functions)
            features['crypto_functions'] = float(crypto_functions)
            features['time_functions'] = float(time_functions)
            
            # Analyze strings referenced in code
            strings = r2.cmd('iz')
            code_strings = 0
            for line in strings.split('\n'):
                if 'license' in line.lower() or 'serial' in line.lower():
                    code_strings += 1
            
            features['code_string_refs'] = float(code_strings)
            
            # Check for anti-debugging
            anti_debug_instructions = ['int3', 'int 0x03', 'IsDebuggerPresent', 'CheckRemoteDebugger']
            anti_debug_count = 0
            
            # Sample first few functions for anti-debug
            for func in functions[:20]:  # Limit to first 20 functions for performance
                try:
                    disasm = r2.cmd(f'pdf @ {func.get("offset", 0)}')
                    for instruction in anti_debug_instructions:
                        if instruction in disasm:
                            anti_debug_count += 1
                except:
                    continue
            
            features['anti_debug_instructions'] = float(anti_debug_count)
            
            # Check for indirect calls (obfuscation)
            indirect_calls = r2.cmd('axtj @@ fcn.*')
            features['has_indirect_calls'] = float(len(indirect_calls) > 100)
            
            r2.quit()
            
        except Exception as e:
            logger.debug(f"Code feature extraction error: {e}")
            features.update({
                'function_count': 0.0,
                'licensing_functions': 0.0,
                'crypto_functions': 0.0,
                'time_functions': 0.0,
                'code_string_refs': 0.0,
                'anti_debug_instructions': 0.0,
                'has_indirect_calls': 0.0
            })
        
        return features
    
    def _detect_licensing_schemes(self, binary_path: str) -> Dict[str, float]:
        """Detect known licensing schemes"""
        features = {}
        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Check for each known licensing scheme
            for scheme_name, scheme_data in self.licensing_schemes.items():
                score = 0.0
                
                # Check for characteristic strings
                for string in scheme_data['strings']:
                    if string.encode() in data or string.encode('utf-16le') in data:
                        score += 1.0
                
                # Check for associated files (would need directory context)
                # This is a simplified check
                for filename in scheme_data['files']:
                    if filename.encode() in data:
                        score += 0.5
                
                # Normalize score
                max_score = len(scheme_data['strings']) + (len(scheme_data['files']) * 0.5)
                if max_score > 0:
                    score = score / max_score
                
                features[f'scheme_{scheme_name}_score'] = score
            
            # Detect custom licensing (high licensing indicators but low known scheme scores)
            known_scheme_total = sum(features[f'scheme_{s}_score'] for s in self.licensing_schemes if s != 'custom')
            if known_scheme_total < 0.3:  # Low known scheme detection
                features['scheme_custom_score'] = min(1.0, features.get('strings_license_text_count', 0) / 10.0)
            
        except Exception as e:
            logger.debug(f"Licensing scheme detection error: {e}")
            for scheme_name in self.licensing_schemes:
                features[f'scheme_{scheme_name}_score'] = 0.0
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate probabilities
        probabilities = byte_counts / len(data)
        
        # Calculate entropy
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_licensing_score(self, features: Dict[str, float]) -> float:
        """Calculate overall licensing complexity score"""
        score = 0.0
        
        # Weight different aspects
        weights = {
            'imports_registry_count': 0.1,
            'imports_crypto_count': 0.15,
            'imports_network_count': 0.1,
            'imports_time_count': 0.1,
            'imports_hardware_count': 0.15,
            'strings_license_text_count': 0.15,
            'strings_license_keys_count': 0.1,
            'licensing_functions': 0.1,
            'has_license_key_pattern': 0.05
        }
        
        for feature, weight in weights.items():
            if feature in features:
                # Normalize feature value (cap at 10 for counts)
                normalized_value = min(1.0, features[feature] / 10.0)
                score += normalized_value * weight
        
        # Bonus for known licensing schemes
        for scheme in self.licensing_schemes:
            if features.get(f'scheme_{scheme}_score', 0) > 0.5:
                score += 0.2
                break
        
        return min(1.0, score)
    
    def _calculate_protection_level(self, features: Dict[str, float]) -> float:
        """Calculate protection/obfuscation level"""
        score = 0.0
        
        # Factors indicating protection
        if features.get('is_packed', 0) > 0:
            score += 0.3
        
        if features.get('high_entropy_sections', 0) > 1:
            score += 0.2
        
        if features.get('anti_debug_instructions', 0) > 0:
            score += 0.2
        
        if features.get('has_indirect_calls', 0) > 0:
            score += 0.1
        
        if features.get('imports_protection_count', 0) > 5:
            score += 0.2
        
        return min(1.0, score)
    
    def _get_default_features(self) -> Dict[str, float]:
        """Get default feature values"""
        features = {}
        
        # File features
        features.update({
            'file_size': 0.0,
            'entropy': 5.0,
            'is_packed': 0.0,
            'is_pe': 0.0,
            'is_elf': 0.0,
            'has_digital_signature': 0.0
        })
        
        # Import features
        for category in self.licensing_apis:
            features[f'imports_{category}_count'] = 0.0
        
        # String features
        for category in self.licensing_strings:
            features[f'strings_{category}_count'] = 0.0
        
        # Code features
        features.update({
            'function_count': 0.0,
            'licensing_functions': 0.0,
            'crypto_functions': 0.0,
            'time_functions': 0.0,
            'code_string_refs': 0.0,
            'anti_debug_instructions': 0.0,
            'has_indirect_calls': 0.0
        })
        
        # Scheme features
        for scheme in self.licensing_schemes:
            features[f'scheme_{scheme}_score'] = 0.0
        
        # Composite scores
        features.update({
            'licensing_score': 0.0,
            'protection_level': 0.0
        })
        
        return features