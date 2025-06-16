"""
Radare2 FLIRT Signature Analysis and Function Identification Engine

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
from typing import Any, Dict, List, Optional

from ...utils.radare2_utils import R2Exception, R2Session, r2_session


class R2SignatureAnalyzer:
    """
    Advanced signature analysis engine using radare2's FLIRT and Zignature capabilities.
    
    Provides sophisticated function identification for:
    - Library function recognition
    - Compiler runtime identification
    - Crypto algorithm detection
    - Anti-analysis technique identification
    - License validation routine recognition
    - Known vulnerability pattern detection
    """

    def __init__(self, binary_path: str, radare2_path: Optional[str] = None):
        """
        Initialize signature analyzer.
        
        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable
        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.signature_cache = {}
        self.custom_signatures = {}

    def analyze_signatures(self) -> Dict[str, Any]:
        """
        Perform comprehensive signature analysis on the binary.
        
        Returns:
            Complete signature analysis results
        """
        result = {
            'binary_path': self.binary_path,
            'flirt_signatures': {},
            'zignature_matches': {},
            'identified_functions': [],
            'library_functions': {},
            'compiler_artifacts': {},
            'crypto_functions': [],
            'anti_analysis_functions': [],
            'license_validation_functions': [],
            'vulnerability_signatures': [],
            'custom_pattern_matches': [],
            'signature_statistics': {},
            'unidentified_functions': [],
            'confidence_analysis': {}
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Apply FLIRT signatures
                result['flirt_signatures'] = self._apply_flirt_signatures(r2)

                # Apply Zignatures
                result['zignature_matches'] = self._apply_zignatures(r2)

                # Get all functions and categorize identified ones
                all_functions = r2.get_functions()
                result['identified_functions'] = self._categorize_identified_functions(all_functions)

                # Analyze library functions
                result['library_functions'] = self._analyze_library_functions(r2, all_functions)

                # Detect compiler artifacts
                result['compiler_artifacts'] = self._detect_compiler_artifacts(r2, all_functions)

                # Identify crypto functions
                result['crypto_functions'] = self._identify_crypto_functions(r2, all_functions)

                # Detect anti-analysis functions
                result['anti_analysis_functions'] = self._detect_anti_analysis_functions(r2, all_functions)

                # Identify license validation functions
                result['license_validation_functions'] = self._identify_license_validation_functions(r2, all_functions)

                # Check for known vulnerability signatures
                result['vulnerability_signatures'] = self._check_vulnerability_signatures(r2, all_functions)

                # Apply custom pattern matching
                result['custom_pattern_matches'] = self._apply_custom_patterns(r2, all_functions)

                # Find unidentified functions
                result['unidentified_functions'] = self._find_unidentified_functions(all_functions)

                # Generate statistics
                result['signature_statistics'] = self._generate_signature_statistics(result)

                # Perform confidence analysis
                result['confidence_analysis'] = self._analyze_identification_confidence(result)

        except R2Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Signature analysis failed: {e}")

        return result

    def _apply_flirt_signatures(self, r2: R2Session) -> Dict[str, Any]:
        """Apply FLIRT signatures to identify library functions."""
        flirt_result = {
            'signatures_applied': 0,
            'functions_identified': 0,
            'signature_files_used': [],
            'matches': []
        }

        try:
            # Apply FLIRT signatures
            r2._execute_command('zf')

            # Get information about applied signatures
            sig_info = r2._execute_command('zi')
            if sig_info:
                flirt_result['signature_info'] = sig_info.strip()

            # Get functions that were identified by signatures
            functions = r2.get_functions()
            identified_by_flirt = []

            for func in functions:
                func_name = func.get('name', '')
                # FLIRT-identified functions typically have specific naming patterns
                if (func_name.startswith('sym.') and not func_name.startswith('sym.imp.') and
                    not func_name.startswith('sym.entry') and len(func_name) > 10):
                    # Get more details about this function
                    func_addr = func.get('offset', 0)
                    if func_addr:
                        try:
                            func_info = r2.get_function_info(func_addr)
                            if func_info:
                                identified_by_flirt.append({
                                    'name': func_name,
                                    'address': hex(func_addr),
                                    'size': func.get('size', 0),
                                    'signature_type': 'flirt'
                                })
                        except R2Exception:
                            continue

            flirt_result['matches'] = identified_by_flirt
            flirt_result['functions_identified'] = len(identified_by_flirt)

        except R2Exception as e:
            flirt_result['error'] = str(e)
            self.logger.debug(f"FLIRT signature application failed: {e}")

        return flirt_result

    def _apply_zignatures(self, r2: R2Session) -> Dict[str, Any]:
        """Apply Zignatures for function identification."""
        zignature_result = {
            'signatures_loaded': 0,
            'matches': [],
            'match_confidence': {}
        }

        try:
            # Check if zignatures are available
            zignature_info = r2._execute_command('z')

            # Search for zignature matches
            zignature_matches = r2._execute_command('zs')
            if zignature_matches:
                # Parse zignature results
                matches = []
                for line in zignature_matches.split('\n'):
                    if line.strip() and 'match' in line.lower():
                        matches.append(line.strip())

                zignature_result['matches'] = matches

            # Get zignature statistics
            zignature_stats = r2._execute_command('zi')
            if zignature_stats:
                zignature_result['statistics'] = zignature_stats.strip()

        except R2Exception as e:
            zignature_result['error'] = str(e)
            self.logger.debug(f"Zignature analysis failed: {e}")

        return zignature_result

    def _categorize_identified_functions(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Categorize functions based on their names and signatures."""
        categorized = []

        for func in functions:
            func_name = func.get('name', '')
            func_addr = func.get('offset', 0)

            category = self._determine_function_category(func_name)

            categorized.append({
                'name': func_name,
                'address': hex(func_addr) if func_addr else '0x0',
                'size': func.get('size', 0),
                'category': category,
                'confidence': self._calculate_name_confidence(func_name),
                'signature_source': self._determine_signature_source(func_name)
            })

        return categorized

    def _determine_function_category(self, func_name: str) -> str:
        """Determine function category based on name patterns."""
        name_lower = func_name.lower()

        # System/API functions
        if (func_name.startswith('sym.imp.') or
            any(prefix in name_lower for prefix in ['get', 'set', 'create', 'delete', 'open', 'close'])):
            return 'system_api'

        # C Runtime functions
        if (func_name.startswith('sym._') or
            any(crt in name_lower for crt in ['malloc', 'free', 'printf', 'scanf', 'strlen', 'strcmp'])):
            return 'c_runtime'

        # Crypto functions
        if any(crypto in name_lower for crypto in ['crypt', 'hash', 'aes', 'des', 'rsa', 'sha', 'md5']):
            return 'cryptographic'

        # String functions
        if any(str_func in name_lower for str_func in ['str', 'mem', 'copy', 'move']):
            return 'string_manipulation'

        # Network functions
        if any(net in name_lower for net in ['socket', 'connect', 'send', 'recv', 'http']):
            return 'network'

        # File I/O functions
        if any(file_func in name_lower for file_func in ['file', 'read', 'write', 'seek']):
            return 'file_io'

        # Registry functions
        if any(reg in name_lower for reg in ['reg', 'key', 'value']):
            return 'registry'

        # User-defined functions
        if func_name.startswith('fcn.') or func_name.startswith('sub_'):
            return 'user_defined'

        # Entry points
        if 'entry' in name_lower or 'main' in name_lower:
            return 'entry_point'

        return 'unknown'

    def _calculate_name_confidence(self, func_name: str) -> float:
        """Calculate confidence level for function identification."""
        # Higher confidence for imported functions
        if func_name.startswith('sym.imp.'):
            return 0.95

        # High confidence for well-known C runtime functions
        known_crt = ['malloc', 'free', 'printf', 'scanf', 'strlen', 'strcmp', 'strcpy', 'memcpy']
        if any(crt in func_name.lower() for crt in known_crt):
            return 0.9

        # Medium confidence for API-like names
        if any(prefix in func_name.lower() for prefix in ['get', 'set', 'create', 'delete']):
            return 0.7

        # Low confidence for generic or mangled names
        if func_name.startswith('fcn.') or func_name.startswith('sub_'):
            return 0.3

        # Medium confidence for other recognized patterns
        return 0.6

    def _determine_signature_source(self, func_name: str) -> str:
        """Determine the source of function signature."""
        if func_name.startswith('sym.imp.'):
            return 'import_table'
        elif func_name.startswith('sym._'):
            return 'flirt_signature'
        elif func_name.startswith('fcn.'):
            return 'analysis_heuristic'
        elif func_name.startswith('sub_'):
            return 'disassembly'
        else:
            return 'signature_database'

    def _analyze_library_functions(self, r2: R2Session, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze and categorize library functions."""
        library_analysis = {
            'c_runtime': [],
            'windows_api': [],
            'posix_api': [],
            'crypto_libraries': [],
            'network_libraries': [],
            'ui_libraries': [],
            'compression_libraries': [],
            'database_libraries': []
        }

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            # C Runtime Library
            if any(crt in name_lower for crt in ['msvcrt', 'ucrt', 'libc', 'malloc', 'free', 'printf']):
                library_analysis['c_runtime'].append(func)

            # Windows API
            elif any(win_api in name_lower for win_api in ['kernel32', 'user32', 'advapi32', 'ntdll']):
                library_analysis['windows_api'].append(func)

            # POSIX API
            elif any(posix in name_lower for posix in ['pthread', 'dlopen', 'mmap', 'fork']):
                library_analysis['posix_api'].append(func)

            # Crypto Libraries
            elif any(crypto in name_lower for crypto in ['openssl', 'crypto', 'bcrypt', 'crypt32']):
                library_analysis['crypto_libraries'].append(func)

            # Network Libraries
            elif any(net in name_lower for net in ['ws2_32', 'wininet', 'winhttp', 'socket']):
                library_analysis['network_libraries'].append(func)

            # UI Libraries
            elif any(ui in name_lower for ui in ['gdi32', 'comctl32', 'shell32', 'ole32']):
                library_analysis['ui_libraries'].append(func)

            # Compression Libraries
            elif any(comp in name_lower for comp in ['zlib', 'bzip2', 'lzma', 'deflate']):
                library_analysis['compression_libraries'].append(func)

            # Database Libraries
            elif any(db in name_lower for db in ['sqlite', 'odbc', 'oledb']):
                library_analysis['database_libraries'].append(func)

        return library_analysis

    def _detect_compiler_artifacts(self, r2: R2Session, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect compiler-specific artifacts and runtime functions."""
        compiler_artifacts = {
            'msvc_artifacts': [],
            'gcc_artifacts': [],
            'clang_artifacts': [],
            'borland_artifacts': [],
            'runtime_checks': [],
            'exception_handling': [],
            'stack_guards': []
        }

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            # MSVC artifacts
            if any(msvc in name_lower for msvc in ['__security_', '__report_', '_crt', '_chk']):
                compiler_artifacts['msvc_artifacts'].append(func)

            # GCC artifacts
            elif any(gcc in name_lower for gcc in ['__stack_chk', '__gxx_', '_gnu_']):
                compiler_artifacts['gcc_artifacts'].append(func)

            # Exception handling
            elif any(eh in name_lower for eh in ['__eh_', '_except_', '__try', '__catch']):
                compiler_artifacts['exception_handling'].append(func)

            # Stack protection
            elif any(stack in name_lower for stack in ['__stack_chk', '__guard', '_security_']):
                compiler_artifacts['stack_guards'].append(func)

            # Runtime checks
            elif any(check in name_lower for check in ['__chk', '_check_', '__valid']):
                compiler_artifacts['runtime_checks'].append(func)

        return compiler_artifacts

    def _identify_crypto_functions(self, r2: R2Session, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify cryptographic functions and algorithms."""
        crypto_functions = []

        crypto_patterns = {
            'aes': ['aes', 'rijndael'],
            'des': ['des', '3des', 'triple'],
            'rsa': ['rsa', 'pubkey'],
            'hash': ['sha', 'md5', 'md4', 'hash'],
            'random': ['rand', 'random', 'prng'],
            'crypto_api': ['crypt', 'cipher', 'encrypt', 'decrypt']
        }

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            for crypto_type, patterns in crypto_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    crypto_functions.append({
                        'function': func,
                        'crypto_type': crypto_type,
                        'patterns_matched': [p for p in patterns if p in name_lower],
                        'confidence': self._calculate_crypto_confidence(func_name, patterns)
                    })
                    break

        return crypto_functions

    def _calculate_crypto_confidence(self, func_name: str, patterns: List[str]) -> float:
        """Calculate confidence for crypto function identification."""
        name_lower = func_name.lower()
        matches = sum(1 for pattern in patterns if pattern in name_lower)

        # Higher confidence for more specific matches
        if 'encrypt' in name_lower or 'decrypt' in name_lower:
            return 0.9
        elif 'crypt' in name_lower:
            return 0.8
        elif matches > 1:
            return 0.7
        else:
            return 0.6

    def _detect_anti_analysis_functions(self, r2: R2Session, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anti-analysis and anti-debugging functions."""
        anti_analysis = []

        anti_patterns = {
            'debugger_detection': ['isdebuggerpresent', 'checkremotedebugger', 'ntqueryinformationprocess'],
            'vm_detection': ['cpuid', 'rdtsc', 'sidt', 'sgdt'],
            'analysis_evasion': ['virtualprotect', 'virtualalloc', 'createthread'],
            'packer_functions': ['unpack', 'decrypt', 'decompress', 'inflate']
        }

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            for category, patterns in anti_patterns.items():
                if any(pattern in name_lower for pattern in patterns):
                    anti_analysis.append({
                        'function': func,
                        'category': category,
                        'patterns_matched': [p for p in patterns if p in name_lower],
                        'risk_level': self._calculate_anti_analysis_risk(func_name, category)
                    })
                    break

        return anti_analysis

    def _calculate_anti_analysis_risk(self, func_name: str, category: str) -> str:
        """Calculate risk level for anti-analysis functions."""
        if category == 'debugger_detection':
            return 'high'
        elif category == 'vm_detection':
            return 'medium'
        elif category == 'analysis_evasion':
            return 'high'
        else:
            return 'low'

    def _identify_license_validation_functions(self, r2: R2Session, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential license validation functions."""
        license_functions = []

        license_patterns = [
            'license', 'registration', 'activation', 'validation', 'authenticate',
            'verify', 'check', 'trial', 'demo', 'expire', 'serial', 'key'
        ]

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            matched_patterns = [pattern for pattern in license_patterns if pattern in name_lower]

            if matched_patterns:
                license_functions.append({
                    'function': func,
                    'patterns_matched': matched_patterns,
                    'confidence': len(matched_patterns) / len(license_patterns),
                    'license_type': self._determine_license_type(func_name)
                })

        return license_functions

    def _determine_license_type(self, func_name: str) -> str:
        """Determine the type of license validation."""
        name_lower = func_name.lower()

        if 'trial' in name_lower or 'demo' in name_lower:
            return 'trial_validation'
        elif 'serial' in name_lower or 'key' in name_lower:
            return 'serial_key_validation'
        elif 'activation' in name_lower:
            return 'activation_validation'
        elif 'registration' in name_lower:
            return 'registration_validation'
        else:
            return 'general_validation'

    def _check_vulnerability_signatures(self, r2: R2Session, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for known vulnerability signatures."""
        vulnerability_sigs = []

        vulnerable_functions = {
            'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
            'format_string': ['printf', 'fprintf', 'snprintf'],
            'integer_overflow': ['malloc', 'calloc', 'realloc'],
            'use_after_free': ['free', 'delete'],
            'race_condition': ['createthread', 'createprocess']
        }

        for func in functions:
            func_name = func.get('name', '')
            name_lower = func_name.lower()

            for vuln_type, patterns in vulnerable_functions.items():
                if any(pattern in name_lower for pattern in patterns):
                    vulnerability_sigs.append({
                        'function': func,
                        'vulnerability_type': vuln_type,
                        'risk_level': self._calculate_vulnerability_risk(vuln_type),
                        'mitigation_needed': True
                    })
                    break

        return vulnerability_sigs

    def _calculate_vulnerability_risk(self, vuln_type: str) -> str:
        """Calculate risk level for vulnerability types."""
        high_risk = ['buffer_overflow', 'format_string', 'use_after_free']
        medium_risk = ['integer_overflow', 'race_condition']

        if vuln_type in high_risk:
            return 'high'
        elif vuln_type in medium_risk:
            return 'medium'
        else:
            return 'low'

    def _apply_custom_patterns(self, r2: R2Session, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply custom signature patterns for specific detection."""
        custom_matches = []

        # Custom patterns for license validation
        custom_patterns = {
            'license_check_complex': r'check.*license|license.*valid|validate.*key',
            'trial_expire': r'trial.*expire|demo.*time|time.*left',
            'registration_check': r'reg.*check|check.*reg|registered',
            'activation_routine': r'activate|activation|serial.*check'
        }

        for func in functions:
            func_name = func.get('name', '')

            for pattern_name, pattern in custom_patterns.items():
                import re
                if re.search(pattern, func_name, re.IGNORECASE):
                    custom_matches.append({
                        'function': func,
                        'pattern_name': pattern_name,
                        'pattern': pattern,
                        'match_type': 'regex'
                    })

        return custom_matches

    def _find_unidentified_functions(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find functions that haven't been identified by signatures."""
        unidentified = []

        for func in functions:
            func_name = func.get('name', '')

            # Functions starting with these prefixes are typically unidentified
            if (func_name.startswith('fcn.') or
                func_name.startswith('sub_') or
                func_name.startswith('loc_')):
                unidentified.append(func)

        return unidentified

    def _generate_signature_statistics(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive signature statistics."""
        stats = {
            'total_functions': 0,
            'identified_functions': 0,
            'unidentified_functions': 0,
            'identification_rate': 0.0,
            'library_function_count': 0,
            'crypto_function_count': 0,
            'anti_analysis_count': 0,
            'license_validation_count': 0,
            'vulnerability_count': 0
        }

        # Count functions
        identified_funcs = result.get('identified_functions', [])
        unidentified_funcs = result.get('unidentified_functions', [])

        stats['total_functions'] = len(identified_funcs) + len(unidentified_funcs)
        stats['identified_functions'] = len(identified_funcs)
        stats['unidentified_functions'] = len(unidentified_funcs)

        if stats['total_functions'] > 0:
            stats['identification_rate'] = stats['identified_functions'] / stats['total_functions']

        # Count specialized functions
        library_funcs = result.get('library_functions', {})
        stats['library_function_count'] = sum(len(funcs) for funcs in library_funcs.values())

        stats['crypto_function_count'] = len(result.get('crypto_functions', []))
        stats['anti_analysis_count'] = len(result.get('anti_analysis_functions', []))
        stats['license_validation_count'] = len(result.get('license_validation_functions', []))
        stats['vulnerability_count'] = len(result.get('vulnerability_signatures', []))

        return stats

    def _analyze_identification_confidence(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze confidence levels of function identification."""
        confidence_analysis = {
            'high_confidence': [],
            'medium_confidence': [],
            'low_confidence': [],
            'average_confidence': 0.0,
            'confidence_distribution': {}
        }

        identified_funcs = result.get('identified_functions', [])

        if not identified_funcs:
            return confidence_analysis

        confidences = []
        for func in identified_funcs:
            confidence = func.get('confidence', 0.0)
            confidences.append(confidence)

            if confidence >= 0.8:
                confidence_analysis['high_confidence'].append(func)
            elif confidence >= 0.5:
                confidence_analysis['medium_confidence'].append(func)
            else:
                confidence_analysis['low_confidence'].append(func)

        confidence_analysis['average_confidence'] = sum(confidences) / len(confidences)

        # Distribution
        confidence_analysis['confidence_distribution'] = {
            'high (>= 0.8)': len(confidence_analysis['high_confidence']),
            'medium (0.5-0.8)': len(confidence_analysis['medium_confidence']),
            'low (< 0.5)': len(confidence_analysis['low_confidence'])
        }

        return confidence_analysis


def analyze_binary_signatures(binary_path: str, radare2_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform comprehensive signature analysis on a binary.
    
    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        
    Returns:
        Complete signature analysis results
    """
    analyzer = R2SignatureAnalyzer(binary_path, radare2_path)
    return analyzer.analyze_signatures()


__all__ = ['R2SignatureAnalyzer', 'analyze_binary_signatures']
