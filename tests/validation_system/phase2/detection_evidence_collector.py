"""Phase 2 Detection Evidence Collector for Intellicrack Validation System.

This module implements comprehensive evidence collection for protection detection
validation, integrating with Intellicrack's existing binary analysis infrastructure
to provide undeniable proof of detection capabilities.

Copyright (C) 2025 Zachary Flint

This file is part of the Intellicrack Validation Framework.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import r2pipe
    HAS_R2PIPE = True
except ImportError:
    HAS_R2PIPE = False
    r2pipe = None

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    capstone = None

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    yara = None

# Import Intellicrack modules for integration
try:
    from intellicrack.core.analysis.memory_forensics_engine import MemoryForensicsEngine
    from intellicrack.core.analysis.radare2_imports import ImportAnalyzer
    from intellicrack.core.analysis.radare2_signatures import RadareSignatureEngine
    from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
    from intellicrack.core.binary_analyzer import BinaryAnalyzer
    from intellicrack.core.protection_analyzer import ProtectionAnalyzer
    from intellicrack.utils.logger import get_logger
    HAS_INTELLICRACK_MODULES = True
except ImportError:
    HAS_INTELLICRACK_MODULES = False


class DetectionEvidence:
    """Container for evidence collected during protection detection."""

    def __init__(self):
        """Initialize evidence container."""
        self.memory_addresses: List[Dict[str, Any]] = []
        self.disassembly_snippets: List[Dict[str, Any]] = []
        self.import_table_entries: List[Dict[str, Any]] = []
        self.protection_signatures: List[Dict[str, Any]] = []
        self.algorithm_details: Dict[str, Any] = {}
        self.timestamp = time.time()
        self.evidence_hash = ""

    def calculate_evidence_hash(self) -> str:
        """Calculate cryptographic hash of all evidence."""
        evidence_data = {
            'memory_addresses': self.memory_addresses,
            'disassembly_snippets': self.disassembly_snippets,
            'import_table_entries': self.import_table_entries,
            'protection_signatures': self.protection_signatures,
            'algorithm_details': self.algorithm_details,
            'timestamp': self.timestamp
        }
        evidence_json = json.dumps(evidence_data, sort_keys=True, default=str)
        self.evidence_hash = hashlib.sha256(evidence_json.encode()).hexdigest()
        return self.evidence_hash

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary format."""
        return {
            'memory_addresses': self.memory_addresses,
            'disassembly_snippets': self.disassembly_snippets,
            'import_table_entries': self.import_table_entries,
            'protection_signatures': self.protection_signatures,
            'algorithm_details': self.algorithm_details,
            'timestamp': self.timestamp,
            'evidence_hash': self.evidence_hash
        }


class DetectionEvidenceCollector:
    """Comprehensive evidence collector for protection detection validation.

    This class integrates with Intellicrack's binary analysis infrastructure
    to collect undeniable evidence of protection detection capabilities.
    """

    def __init__(self, binary_path: Path, logger: Optional[logging.Logger] = None):
        """Initialize evidence collector.

        Args:
            binary_path: Path to binary file for analysis
            logger: Optional logger instance
        """
        self.binary_path = Path(binary_path)
        self.logger = logger or get_logger(__name__)
        self.evidence = DetectionEvidence()

        # Validate dependencies
        self._validate_dependencies()

        # Initialize Intellicrack modules
        self._initialize_intellicrack_modules()

    def _validate_dependencies(self) -> None:
        """Validate required dependencies are available."""
        missing_deps = []

        if not HAS_R2PIPE:
            missing_deps.append("r2pipe")
        if not HAS_CAPSTONE:
            missing_deps.append("capstone")
        if not HAS_YARA:
            missing_deps.append("yara-python")
        if not HAS_INTELLICRACK_MODULES:
            missing_deps.append("intellicrack modules")

        if missing_deps:
            raise ImportError(
                f"Missing required dependencies: {', '.join(missing_deps)}"
            )

    def _initialize_intellicrack_modules(self) -> None:
        """Initialize Intellicrack analysis modules."""
        try:
            self.binary_analyzer = BinaryAnalyzer()
            self.protection_analyzer = ProtectionAnalyzer()
            self.signature_engine = RadareSignatureEngine()
            self.import_analyzer = ImportAnalyzer()
            self.yara_engine = YaraPatternEngine()
            self.memory_engine = MemoryForensicsEngine()

            self.logger.info("Initialized Intellicrack modules successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize Intellicrack modules: {e}")
            raise

    def collect_memory_addresses(self, protection_name: str) -> List[Dict[str, Any]]:
        """Collect memory addresses where protection code is located.

        Args:
            protection_name: Name of detected protection

        Returns:
            List of memory address evidence with verification
        """
        self.logger.info(f"Collecting memory addresses for {protection_name}")

        try:
            # Use radare2 to analyze binary and find protection code locations
            with r2pipe.open(str(self.binary_path)) as r2:
                # Analyze binary structure
                r2.cmd('aaa')  # Analyze all

                # Get function addresses
                functions = r2.cmdj('aflj')
                if not functions:
                    functions = []

                # Get section information
                sections = r2.cmdj('iSj')
                if not sections:
                    sections = []

                # Find addresses related to protection
                protection_addresses = []

                for func in functions:
                    func_name = func.get('name', '').lower()
                    if any(prot_term in func_name for prot_term in
                           ['license', 'protection', 'drm', 'check', 'validate']):

                        # Get disassembly at this address
                        addr = func.get('offset', 0)
                        disasm = r2.cmd(f'pd 20 @ {addr}')

                        # Verify this is actually protection-related code
                        if self._is_protection_code(disasm, protection_name):
                            protection_addresses.append({
                                'address': hex(addr),
                                'function_name': func.get('name', 'unknown'),
                                'size': func.get('size', 0),
                                'verification_method': 'radare2_function_analysis',
                                'disassembly_preview': disasm.split('\n')[:5],
                                'timestamp': time.time()
                            })

                # Search for protection-specific byte patterns
                pattern_addresses = self._find_protection_patterns(r2, protection_name)
                protection_addresses.extend(pattern_addresses)

                self.evidence.memory_addresses = protection_addresses
                self.logger.info(f"Found {len(protection_addresses)} protection addresses")

                return protection_addresses

        except Exception as e:
            self.logger.error(f"Failed to collect memory addresses: {e}")
            raise

    def _is_protection_code(self, disassembly: str, protection_name: str) -> bool:
        """Verify if disassembly contains protection-related code.

        Args:
            disassembly: Assembly code to analyze
            protection_name: Name of protection to verify

        Returns:
            True if code appears to be protection-related
        """
        # Define protection-specific patterns
        protection_patterns = {
            'flexlm': ['call.*flex', 'lm_.*', 'checkout', 'heartbeat'],
            'adobe': ['adobe', 'amtlib', 'oobe', 'activation'],
            'hasp': ['hasp', 'sentinel', 'dongle', 'hardware'],
            'safenet': ['safenet', 'rainbow', 'crypto'],
            'armadillo': ['armadillo', 'nanomites', 'copylock']
        }

        prot_key = protection_name.lower().split()[0]
        patterns = protection_patterns.get(prot_key, [])

        disasm_lower = disassembly.lower()
        return any(pattern in disasm_lower for pattern in patterns)

    def _find_protection_patterns(self, r2, protection_name: str) -> List[Dict[str, Any]]:
        """Find addresses containing protection-specific byte patterns.

        Args:
            r2: Radare2 pipe instance
            protection_name: Name of protection to search for

        Returns:
            List of addresses with protection patterns
        """
        pattern_addresses = []

        # Define known protection byte patterns
        protection_signatures = {
            'flexlm': [
                b'\x00\x00\x00\x00\x46\x4C\x45\x58\x6C\x6D',  # FLEXlm signature
                b'\x6C\x6D\x5F\x63\x68\x65\x63\x6B\x6F\x75\x74'  # lm_checkout
            ],
            'adobe': [
                b'\x41\x64\x6F\x62\x65\x00',  # Adobe null-terminated
                b'\x61\x6D\x74\x6C\x69\x62'   # amtlib
            ],
            'hasp': [
                b'\x48\x41\x53\x50',  # HASP
                b'\x53\x65\x6E\x74\x69\x6E\x65\x6C'  # Sentinel
            ]
        }

        prot_key = protection_name.lower().split()[0]
        signatures = protection_signatures.get(prot_key, [])

        for signature in signatures:
            # Convert bytes to hex string for radare2 search
            hex_pattern = signature.hex()

            # Search for pattern in binary
            results = r2.cmd(f'/x {hex_pattern}')

            if results:
                for line in results.strip().split('\n'):
                    if line.startswith('0x'):
                        addr_str = line.split()[0]
                        try:
                            # Get context around found pattern
                            context = r2.cmd(f'px 64 @ {addr_str}')

                            pattern_addresses.append({
                                'address': addr_str,
                                'pattern': hex_pattern,
                                'verification_method': 'byte_pattern_search',
                                'context': context,
                                'timestamp': time.time()
                            })

                        except ValueError:
                            continue

        return pattern_addresses

    def capture_disassembly_snippets(self, addresses: List[str]) -> List[Dict[str, Any]]:
        """Capture disassembly snippets at specified addresses.

        Args:
            addresses: List of memory addresses to disassemble

        Returns:
            List of disassembly snippets with analysis
        """
        self.logger.info(f"Capturing disassembly at {len(addresses)} addresses")

        disasm_snippets = []

        try:
            with r2pipe.open(str(self.binary_path)) as r2:
                r2.cmd('aaa')  # Ensure analysis is complete

                for addr in addresses:
                    # Get disassembly at address
                    disasm = r2.cmd(f'pd 20 @ {addr}')

                    # Get function information
                    func_info = r2.cmdj(f'afij @ {addr}')
                    if func_info:
                        func_info = func_info[0] if func_info else {}
                    else:
                        func_info = {}

                    # Analyze instruction types and patterns
                    analysis = self._analyze_disassembly(disasm)

                    snippet = {
                        'address': addr,
                        'disassembly': disasm,
                        'function_info': func_info,
                        'instruction_analysis': analysis,
                        'timestamp': time.time()
                    }

                    disasm_snippets.append(snippet)

                self.evidence.disassembly_snippets = disasm_snippets
                self.logger.info(f"Captured {len(disasm_snippets)} disassembly snippets")

                return disasm_snippets

        except Exception as e:
            self.logger.error(f"Failed to capture disassembly: {e}")
            raise

    def _analyze_disassembly(self, disassembly: str) -> Dict[str, Any]:
        """Analyze disassembly for protection-related patterns.

        Args:
            disassembly: Assembly code to analyze

        Returns:
            Analysis results including instruction types and patterns
        """
        lines = disassembly.strip().split('\n')

        analysis = {
            'instruction_count': len(lines),
            'call_instructions': 0,
            'jump_instructions': 0,
            'crypto_operations': 0,
            'string_references': [],
            'api_calls': [],
            'protection_indicators': []
        }

        for line in lines:
            if not line.strip():
                continue

            # Count instruction types
            if 'call' in line:
                analysis['call_instructions'] += 1
                # Extract API call if present
                if '.' in line and ('dll' in line.lower() or 'api' in line.lower()):
                    analysis['api_calls'].append(line.strip())

            elif any(jmp in line for jmp in ['jmp', 'je', 'jne', 'jz', 'jnz']):
                analysis['jump_instructions'] += 1

            # Look for crypto operations
            if any(crypto in line.lower() for crypto in ['xor', 'and', 'or', 'shl', 'shr']):
                analysis['crypto_operations'] += 1

            # Look for string references
            if '"' in line:
                start = line.find('"')
                end = line.find('"', start + 1)
                if end != -1:
                    string_ref = line[start:end+1]
                    analysis['string_references'].append(string_ref)

            # Look for protection indicators
            if any(indicator in line.lower() for indicator in
                   ['license', 'protect', 'drm', 'check', 'valid']):
                analysis['protection_indicators'].append(line.strip())

        return analysis

    def extract_import_table_entries(self) -> List[Dict[str, Any]]:
        """Extract import table entries related to protection mechanisms.

        Returns:
            List of protection-related import entries
        """
        self.logger.info("Extracting protection-related import table entries")

        try:
            # Use Intellicrack's import analyzer
            import_data = self.import_analyzer.analyze_imports(self.binary_path)

            protection_imports = []

            # Define protection-related API patterns
            protection_apis = {
                'licensing': ['CreateMutex', 'RegOpenKey', 'RegQueryValue', 'GetComputerName'],
                'crypto': ['CryptAcquireContext', 'CryptCreateHash', 'CryptHashData'],
                'hardware': ['GetVolumeInformation', 'GetDiskFreeSpace', 'DeviceIoControl'],
                'network': ['WinHttpOpen', 'InternetOpen', 'HttpSendRequest'],
                'time': ['GetSystemTime', 'GetTickCount', 'QueryPerformanceCounter'],
                'debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']
            }

            if import_data and 'imports' in import_data:
                for dll_name, functions in import_data['imports'].items():
                    for func in functions:
                        func_name = func.get('name', '')

                        # Check if function is protection-related
                        for category, apis in protection_apis.items():
                            if any(api.lower() in func_name.lower() for api in apis):
                                protection_imports.append({
                                    'dll': dll_name,
                                    'function': func_name,
                                    'category': category,
                                    'address': func.get('address'),
                                    'ordinal': func.get('ordinal'),
                                    'timestamp': time.time()
                                })
                                break

            # Also check for protection-specific DLL imports
            protection_dlls = ['amtlib.dll', 'flexlm.dll', 'hasplms.dll', 'sentinel.dll']

            if import_data and 'dlls' in import_data:
                for dll in import_data['dlls']:
                    dll_name = dll.lower()
                    if any(prot_dll in dll_name for prot_dll in protection_dlls):
                        protection_imports.append({
                            'dll': dll,
                            'function': '*',  # Entire DLL is protection-related
                            'category': 'protection_library',
                            'address': None,
                            'ordinal': None,
                            'timestamp': time.time()
                        })

            self.evidence.import_table_entries = protection_imports
            self.logger.info(f"Found {len(protection_imports)} protection-related imports")

            return protection_imports

        except Exception as e:
            self.logger.error(f"Failed to extract import table entries: {e}")
            raise

    def generate_protection_signatures(self, protection_name: str) -> List[Dict[str, Any]]:
        """Generate cryptographic hashes of protection signatures found.

        Args:
            protection_name: Name of detected protection

        Returns:
            List of protection signatures with hashes
        """
        self.logger.info(f"Generating signatures for {protection_name}")

        signatures = []

        try:
            # Use Intellicrack's signature engine
            sig_results = self.signature_engine.detect_signatures(
                self.binary_path,
                focus_protection=protection_name
            )

            for result in sig_results:
                # Calculate hash of signature pattern
                pattern_data = result.get('pattern', b'')
                if isinstance(pattern_data, str):
                    pattern_data = pattern_data.encode()

                sig_hash = hashlib.sha256(pattern_data).hexdigest()

                signatures.append({
                    'name': result.get('name'),
                    'pattern': pattern_data.hex() if pattern_data else '',
                    'offset': result.get('offset'),
                    'size': result.get('size'),
                    'confidence': result.get('confidence'),
                    'signature_hash': sig_hash,
                    'detection_method': 'intellicrack_signature_engine',
                    'timestamp': time.time()
                })

            # Also generate signatures from memory addresses found
            for addr_info in self.evidence.memory_addresses:
                addr = addr_info['address']

                # Read bytes at address and create signature
                with r2pipe.open(str(self.binary_path)) as r2:
                    # Read 32 bytes at address
                    hex_bytes = r2.cmd(f'px 32 @ {addr}')

                    if hex_bytes:
                        # Parse hex output and create signature
                        byte_pattern = self._parse_hex_output(hex_bytes)
                        if byte_pattern:
                            sig_hash = hashlib.sha256(byte_pattern).hexdigest()

                            signatures.append({
                                'name': f'memory_signature_{addr}',
                                'pattern': byte_pattern.hex(),
                                'offset': addr,
                                'size': len(byte_pattern),
                                'confidence': 0.8,
                                'signature_hash': sig_hash,
                                'detection_method': 'memory_address_signature',
                                'timestamp': time.time()
                            })

            self.evidence.protection_signatures = signatures
            self.logger.info(f"Generated {len(signatures)} protection signatures")

            return signatures

        except Exception as e:
            self.logger.error(f"Failed to generate protection signatures: {e}")
            raise

    def _parse_hex_output(self, hex_output: str) -> Optional[bytes]:
        """Parse radare2 hex output into bytes.

        Args:
            hex_output: Hex output from radare2

        Returns:
            Parsed bytes or None if parsing fails
        """
        try:
            # Extract hex bytes from radare2 output
            hex_chars = ''
            for line in hex_output.split('\n'):
                if line.startswith('-') or not line.strip():
                    continue

                # Find hex part (after address)
                parts = line.split()
                if len(parts) > 1:
                    hex_part = parts[1]
                    hex_chars += hex_part.replace(' ', '')

            # Convert to bytes
            if len(hex_chars) % 2 == 0:
                return bytes.fromhex(hex_chars[:64])  # Limit to 32 bytes

        except Exception as e:
            logging.debug(f"Failed to extract hex data from line: {e}")

        return None

    def document_algorithm_details(self, protection_name: str) -> Dict[str, Any]:
        """Document protection algorithm details (RSA key size, encryption type, etc.).

        Args:
            protection_name: Name of detected protection

        Returns:
            Dictionary containing algorithm details
        """
        self.logger.info(f"Documenting algorithm details for {protection_name}")

        algorithm_details = {
            'protection_name': protection_name,
            'analysis_timestamp': time.time(),
            'encryption_methods': [],
            'key_sizes': [],
            'hash_algorithms': [],
            'crypto_libraries': [],
            'analysis_confidence': 0.0
        }

        try:
            # Analyze strings for cryptographic indicators
            strings_data = self._extract_crypto_strings()
            algorithm_details.update(strings_data)

            # Analyze imports for crypto APIs
            crypto_imports = self._analyze_crypto_imports()
            algorithm_details['crypto_libraries'] = crypto_imports

            # Analyze code patterns for crypto operations
            crypto_patterns = self._detect_crypto_patterns()
            algorithm_details['encryption_methods'].extend(crypto_patterns)

            # Calculate confidence based on evidence
            confidence = self._calculate_algorithm_confidence(algorithm_details)
            algorithm_details['analysis_confidence'] = confidence

            self.evidence.algorithm_details = algorithm_details
            self.logger.info(f"Documented algorithm details with {confidence:.2f} confidence")

            return algorithm_details

        except Exception as e:
            self.logger.error(f"Failed to document algorithm details: {e}")
            raise

    def _extract_crypto_strings(self) -> Dict[str, Any]:
        """Extract cryptography-related strings from binary."""
        crypto_data = {
            'rsa_indicators': [],
            'aes_indicators': [],
            'hash_indicators': [],
            'cert_indicators': []
        }

        try:
            with r2pipe.open(str(self.binary_path)) as r2:
                # Extract all strings
                strings = r2.cmdj('izj')
                if not strings:
                    strings = []

                for string_info in strings:
                    string_val = string_info.get('string', '').lower()

                    # Look for RSA indicators
                    if any(rsa_term in string_val for rsa_term in
                           ['rsa', 'public key', 'private key', '-----begin']):
                        crypto_data['rsa_indicators'].append(string_val)

                        # Try to extract key size
                        for size in ['1024', '2048', '4096']:
                            if size in string_val:
                                if 'key_sizes' not in crypto_data:
                                    crypto_data['key_sizes'] = []
                                crypto_data['key_sizes'].append(int(size))

                    # Look for AES indicators
                    elif any(aes_term in string_val for aes_term in
                             ['aes', 'rijndael', 'cipher']):
                        crypto_data['aes_indicators'].append(string_val)

                    # Look for hash indicators
                    elif any(hash_term in string_val for hash_term in
                             ['sha', 'md5', 'hash', 'digest']):
                        crypto_data['hash_indicators'].append(string_val)

                    # Look for certificate indicators
                    elif any(cert_term in string_val for cert_term in
                             ['certificate', 'x.509', 'pkcs', 'cert']):
                        crypto_data['cert_indicators'].append(string_val)

        except Exception as e:
            self.logger.debug(f"Error extracting crypto strings: {e}")

        return crypto_data

    def _analyze_crypto_imports(self) -> List[str]:
        """Analyze imports for cryptographic libraries."""
        crypto_libs = []

        try:
            # Get import data from evidence or re-analyze
            if not self.evidence.import_table_entries:
                self.extract_import_table_entries()

            for import_entry in self.evidence.import_table_entries:
                dll = import_entry.get('dll', '').lower()
                func = import_entry.get('function', '').lower()

                # Check for crypto DLLs
                if any(crypto_dll in dll for crypto_dll in
                       ['crypt32', 'advapi32', 'bcrypt', 'ncrypt']):
                    crypto_libs.append(dll)

                # Check for crypto functions
                elif any(crypto_func in func for crypto_func in
                         ['crypt', 'hash', 'encrypt', 'decrypt', 'sign', 'verify']):
                    crypto_libs.append(f"{dll}:{func}")

        except Exception as e:
            self.logger.debug(f"Error analyzing crypto imports: {e}")

        return list(set(crypto_libs))  # Remove duplicates

    def _detect_crypto_patterns(self) -> List[str]:
        """Detect cryptographic operation patterns in code."""
        crypto_patterns = []

        try:
            # Analyze disassembly snippets for crypto patterns
            for snippet in self.evidence.disassembly_snippets:
                disasm = snippet.get('disassembly', '')

                # Look for XOR patterns (common in encryption)
                if 'xor' in disasm and disasm.count('xor') > 5:
                    crypto_patterns.append('xor_encryption_pattern')

                # Look for shift operations (crypto algorithms)
                if any(shift in disasm for shift in ['shl', 'shr', 'rol', 'ror']):
                    crypto_patterns.append('bit_manipulation_crypto')

                # Look for loop patterns with crypto operations
                if 'loop' in disasm and any(op in disasm for op in ['xor', 'add', 'sub']):
                    crypto_patterns.append('crypto_loop_pattern')

        except Exception as e:
            self.logger.debug(f"Error detecting crypto patterns: {e}")

        return list(set(crypto_patterns))

    def _calculate_algorithm_confidence(self, details: Dict[str, Any]) -> float:
        """Calculate confidence in algorithm analysis."""
        confidence = 0.0

        # Base confidence from evidence types
        if details.get('rsa_indicators'):
            confidence += 0.3
        if details.get('key_sizes'):
            confidence += 0.2
        if details.get('crypto_libraries'):
            confidence += 0.2
        if details.get('encryption_methods'):
            confidence += 0.2
        if details.get('hash_indicators'):
            confidence += 0.1

        return min(confidence, 1.0)

    def collect_all_evidence(self, protection_name: str) -> DetectionEvidence:
        """Collect all evidence for protection detection validation.

        Args:
            protection_name: Name of detected protection

        Returns:
            Complete evidence collection
        """
        self.logger.info(f"Collecting all evidence for {protection_name}")

        try:
            # Collect memory addresses
            addresses = self.collect_memory_addresses(protection_name)
            addr_list = [addr['address'] for addr in addresses]

            # Capture disassembly at found addresses
            if addr_list:
                self.capture_disassembly_snippets(addr_list)

            # Extract import table entries
            self.extract_import_table_entries()

            # Generate protection signatures
            self.generate_protection_signatures(protection_name)

            # Document algorithm details
            self.document_algorithm_details(protection_name)

            # Calculate final evidence hash
            self.evidence.calculate_evidence_hash()

            self.logger.info(f"Evidence collection complete. Hash: {self.evidence.evidence_hash}")

            return self.evidence

        except Exception as e:
            self.logger.error(f"Failed to collect evidence: {e}")
            raise

    def save_evidence(self, output_path: Path) -> None:
        """Save collected evidence to file.

        Args:
            output_path: Path where evidence should be saved
        """
        try:
            evidence_data = self.evidence.to_dict()

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(evidence_data, f, indent=2, default=str)

            self.logger.info(f"Evidence saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Failed to save evidence: {e}")
            raise

    def load_evidence(self, input_path: Path) -> DetectionEvidence:
        """Load evidence from file.

        Args:
            input_path: Path to evidence file

        Returns:
            Loaded evidence
        """
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                evidence_data = json.load(f)

            # Reconstruct evidence object
            evidence = DetectionEvidence()
            evidence.memory_addresses = evidence_data.get('memory_addresses', [])
            evidence.disassembly_snippets = evidence_data.get('disassembly_snippets', [])
            evidence.import_table_entries = evidence_data.get('import_table_entries', [])
            evidence.protection_signatures = evidence_data.get('protection_signatures', [])
            evidence.algorithm_details = evidence_data.get('algorithm_details', {})
            evidence.timestamp = evidence_data.get('timestamp', time.time())
            evidence.evidence_hash = evidence_data.get('evidence_hash', '')

            self.evidence = evidence
            self.logger.info(f"Evidence loaded from {input_path}")

            return evidence

        except Exception as e:
            self.logger.error(f"Failed to load evidence: {e}")
            raise
