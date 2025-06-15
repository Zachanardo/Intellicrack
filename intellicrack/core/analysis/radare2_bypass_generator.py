"""
Radare2 Automated License Bypass Generation System

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

import json
import logging
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from ...utils.radare2_utils import r2_session, R2Exception
from .radare2_decompiler import R2DecompilationEngine
from .radare2_vulnerability_engine import R2VulnerabilityEngine
from .radare2_ai_integration import R2AIEngine


class R2BypassGenerator:
    """
    Advanced automated license bypass generation system using radare2 analysis.
    
    Provides comprehensive bypass generation through:
    - Automated patch generation
    - Multi-strategy bypass approaches
    - Binary modification techniques
    - Validation bypass methods
    - Keygen algorithm generation
    - Registration bypass creation
    """

    def __init__(self, binary_path: str, radare2_path: Optional[str] = None):
        """Initialize bypass generator."""
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        
        # Initialize analysis engines
        self.decompiler = R2DecompilationEngine(binary_path, radare2_path)
        self.vulnerability_engine = R2VulnerabilityEngine(binary_path, radare2_path)
        self.ai_engine = R2AIEngine(binary_path, radare2_path)

    def generate_comprehensive_bypass(self) -> Dict[str, Any]:
        """Generate comprehensive license bypass solutions."""
        result = {
            'binary_path': self.binary_path,
            'bypass_strategies': [],
            'automated_patches': [],
            'keygen_algorithms': [],
            'registry_modifications': [],
            'file_modifications': [],
            'memory_patches': [],
            'api_hooks': [],
            'validation_bypasses': [],
            'success_probability': {},
            'implementation_guide': {},
            'risk_assessment': {}
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Analyze license validation mechanisms
                license_analysis = self._analyze_license_mechanisms(r2)
                
                # Generate bypass strategies
                result['bypass_strategies'] = self._generate_bypass_strategies(license_analysis)
                
                # Generate automated patches
                result['automated_patches'] = self._generate_automated_patches(r2, license_analysis)
                
                # Generate keygen algorithms
                result['keygen_algorithms'] = self._generate_keygen_algorithms(license_analysis)
                
                # Generate registry modifications
                result['registry_modifications'] = self._generate_registry_modifications(license_analysis)
                
                # Generate file modifications
                result['file_modifications'] = self._generate_file_modifications(license_analysis)
                
                # Generate memory patches
                result['memory_patches'] = self._generate_memory_patches(r2, license_analysis)
                
                # Generate API hooks
                result['api_hooks'] = self._generate_api_hooks(license_analysis)
                
                # Generate validation bypasses
                result['validation_bypasses'] = self._generate_validation_bypasses(license_analysis)
                
                # Calculate success probabilities
                result['success_probability'] = self._calculate_success_probabilities(result)
                
                # Generate implementation guide
                result['implementation_guide'] = self._generate_implementation_guide(result)
                
                # Assess risks
                result['risk_assessment'] = self._assess_bypass_risks(result)

        except R2Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Bypass generation failed: {e}")

        return result

    def _analyze_license_mechanisms(self, r2) -> Dict[str, Any]:
        """Analyze license validation mechanisms in detail."""
        analysis = {
            'validation_functions': [],
            'crypto_operations': [],
            'string_patterns': [],
            'registry_operations': [],
            'file_operations': [],
            'network_operations': [],
            'time_checks': [],
            'hardware_checks': [],
            'validation_flow': []
        }

        try:
            # Get functions that might be license-related
            functions = r2.get_functions()
            license_functions = [
                f for f in functions 
                if any(keyword in f.get('name', '').lower() 
                      for keyword in ['license', 'valid', 'check', 'trial', 'register', 'activ'])
            ]

            # Analyze each license function
            for func in license_functions:
                func_addr = func.get('offset', 0)
                if func_addr:
                    # Decompile function
                    decompiled = self.decompiler.decompile_function(func_addr)
                    
                    # Extract validation logic
                    validation_info = self._extract_validation_logic(decompiled, func)
                    analysis['validation_functions'].append(validation_info)
                    
                    # Analyze crypto operations
                    crypto_ops = self._extract_crypto_operations(decompiled)
                    analysis['crypto_operations'].extend(crypto_ops)

            # Analyze strings for license patterns
            string_patterns = self._analyze_license_strings(r2)
            analysis['string_patterns'] = string_patterns

            # Analyze API calls for validation mechanisms
            api_analysis = self._analyze_validation_apis(r2)
            analysis.update(api_analysis)

            # Build validation flow
            analysis['validation_flow'] = self._build_validation_flow(analysis)

        except R2Exception as e:
            self.logger.error(f"License mechanism analysis failed: {e}")

        return analysis

    def _extract_validation_logic(self, decompiled: Dict[str, Any], func: Dict[str, Any]) -> Dict[str, Any]:
        """Extract license validation logic from decompiled function."""
        validation_info = {
            'function': func,
            'validation_type': 'unknown',
            'complexity': 'low',
            'bypass_points': [],
            'crypto_usage': False,
            'network_validation': False,
            'time_based': False,
            'hardware_fingerprint': False
        }

        pseudocode = decompiled.get('pseudocode', '')
        license_patterns = decompiled.get('license_patterns', [])

        # Determine validation type
        if any('crypt' in pattern.get('line', '').lower() for pattern in license_patterns):
            validation_info['validation_type'] = 'cryptographic'
            validation_info['crypto_usage'] = True
            validation_info['complexity'] = 'high'

        elif any('network' in pattern.get('line', '').lower() for pattern in license_patterns):
            validation_info['validation_type'] = 'online'
            validation_info['network_validation'] = True
            validation_info['complexity'] = 'high'

        elif any('time' in pattern.get('line', '').lower() for pattern in license_patterns):
            validation_info['validation_type'] = 'time_based'
            validation_info['time_based'] = True
            validation_info['complexity'] = 'medium'

        elif any('hardware' in pattern.get('line', '').lower() for pattern in license_patterns):
            validation_info['validation_type'] = 'hardware_fingerprint'
            validation_info['hardware_fingerprint'] = True
            validation_info['complexity'] = 'medium'

        else:
            validation_info['validation_type'] = 'simple'

        # Find bypass points
        bypass_points = []
        for pattern in license_patterns:
            if pattern.get('type') == 'license_validation':
                bypass_points.append({
                    'line_number': pattern.get('line_number'),
                    'instruction': pattern.get('line'),
                    'bypass_method': self._suggest_bypass_method(pattern)
                })

        validation_info['bypass_points'] = bypass_points

        return validation_info

    def _extract_crypto_operations(self, decompiled: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract cryptographic operations from decompiled code."""
        crypto_ops = []
        
        pseudocode = decompiled.get('pseudocode', '')
        
        # Look for crypto function calls
        crypto_patterns = [
            r'(AES|DES|RSA|SHA|MD5|Hash|Encrypt|Decrypt|Cipher)\w*\s*\(',
            r'Crypt\w*\s*\(',
            r'(Generate|Create)Key\s*\(',
            r'Random\w*\s*\('
        ]

        import re
        lines = pseudocode.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in crypto_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    crypto_ops.append({
                        'line_number': i + 1,
                        'operation': match,
                        'full_line': line.strip(),
                        'algorithm': self._identify_crypto_algorithm(match),
                        'purpose': self._identify_crypto_purpose(line)
                    })

        return crypto_ops

    def _analyze_license_strings(self, r2) -> List[Dict[str, Any]]:
        """Analyze license-related strings."""
        patterns = []
        
        try:
            # Search for license-related strings
            license_keywords = [
                'license', 'serial', 'key', 'activation', 'registration',
                'trial', 'demo', 'expire', 'valid', 'invalid', 'piracy'
            ]

            for keyword in license_keywords:
                try:
                    search_results = r2._execute_command(f'/j {keyword}', expect_json=True)
                    if isinstance(search_results, list):
                        for result in search_results:
                            addr = result.get('offset', 0)
                            if addr:
                                string_content = r2._execute_command(f'ps @ {hex(addr)}')
                                if string_content:
                                    patterns.append({
                                        'keyword': keyword,
                                        'address': hex(addr),
                                        'content': string_content.strip(),
                                        'context': 'license_string',
                                        'bypass_potential': self._assess_string_bypass_potential(string_content)
                                    })
                except R2Exception:
                    continue

        except R2Exception:
            pass

        return patterns

    def _analyze_validation_apis(self, r2) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze API calls used in validation."""
        api_analysis = {
            'registry_operations': [],
            'file_operations': [],
            'network_operations': [],
            'time_checks': [],
            'hardware_checks': []
        }

        try:
            # Get imports
            imports = r2._execute_command('iij', expect_json=True)
            
            if isinstance(imports, list):
                for imp in imports:
                    api_name = imp.get('name', '').lower()
                    
                    # Registry operations
                    if any(reg_api in api_name for reg_api in ['regopen', 'regquery', 'regset']):
                        api_analysis['registry_operations'].append({
                            'api': imp,
                            'purpose': 'license_storage',
                            'bypass_method': 'registry_redirection'
                        })
                    
                    # File operations
                    elif any(file_api in api_name for file_api in ['createfile', 'readfile', 'writefile']):
                        api_analysis['file_operations'].append({
                            'api': imp,
                            'purpose': 'license_file_access',
                            'bypass_method': 'file_redirection'
                        })
                    
                    # Network operations
                    elif any(net_api in api_name for net_api in ['internetopen', 'httpopen', 'connect']):
                        api_analysis['network_operations'].append({
                            'api': imp,
                            'purpose': 'online_validation',
                            'bypass_method': 'network_blocking'
                        })
                    
                    # Time checks
                    elif any(time_api in api_name for time_api in ['getsystemtime', 'getlocaltime']):
                        api_analysis['time_checks'].append({
                            'api': imp,
                            'purpose': 'trial_expiration',
                            'bypass_method': 'time_manipulation'
                        })
                    
                    # Hardware checks
                    elif any(hw_api in api_name for hw_api in ['getvolumeinformation', 'getcomputername']):
                        api_analysis['hardware_checks'].append({
                            'api': imp,
                            'purpose': 'hardware_fingerprint',
                            'bypass_method': 'hardware_spoofing'
                        })

        except R2Exception:
            pass

        return api_analysis

    def _build_validation_flow(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build the validation flow diagram."""
        flow = []
        
        validation_functions = analysis.get('validation_functions', [])
        
        for i, func_info in enumerate(validation_functions):
            flow_step = {
                'step': i + 1,
                'function': func_info['function']['name'],
                'validation_type': func_info['validation_type'],
                'complexity': func_info['complexity'],
                'bypass_difficulty': self._assess_bypass_difficulty(func_info),
                'recommended_approach': self._recommend_bypass_approach(func_info)
            }
            flow.append(flow_step)

        return flow

    def _generate_bypass_strategies(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate bypass strategies based on analysis."""
        strategies = []
        
        validation_functions = license_analysis.get('validation_functions', [])
        
        for func_info in validation_functions:
            validation_type = func_info.get('validation_type', 'unknown')
            
            if validation_type == 'simple':
                strategies.append({
                    'strategy': 'Direct Patching',
                    'description': 'Patch validation checks to always return success',
                    'success_rate': 0.95,
                    'difficulty': 'easy',
                    'implementation': self._generate_direct_patch_implementation(func_info)
                })
            
            elif validation_type == 'cryptographic':
                strategies.append({
                    'strategy': 'Crypto Bypass',
                    'description': 'Bypass cryptographic validation',
                    'success_rate': 0.7,
                    'difficulty': 'medium',
                    'implementation': self._generate_crypto_bypass_implementation(func_info)
                })
            
            elif validation_type == 'online':
                strategies.append({
                    'strategy': 'Network Interception',
                    'description': 'Intercept and modify network validation',
                    'success_rate': 0.8,
                    'difficulty': 'medium',
                    'implementation': self._generate_network_bypass_implementation(func_info)
                })
            
            elif validation_type == 'time_based':
                strategies.append({
                    'strategy': 'Time Manipulation',
                    'description': 'Manipulate system time checks',
                    'success_rate': 0.9,
                    'difficulty': 'easy',
                    'implementation': self._generate_time_bypass_implementation(func_info)
                })

        # Add registry-based strategies
        if license_analysis.get('registry_operations'):
            strategies.append({
                'strategy': 'Registry Manipulation',
                'description': 'Modify registry entries for license validation',
                'success_rate': 0.85,
                'difficulty': 'easy',
                'implementation': self._generate_registry_bypass_implementation(license_analysis)
            })

        return strategies

    def _generate_automated_patches(self, r2, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate automated binary patches."""
        patches = []
        
        validation_functions = license_analysis.get('validation_functions', [])
        
        for func_info in validation_functions:
            bypass_points = func_info.get('bypass_points', [])
            
            for bypass_point in bypass_points:
                patch = self._create_binary_patch(r2, func_info, bypass_point)
                if patch:
                    patches.append(patch)

        return patches

    def _generate_keygen_algorithms(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate keygen algorithms based on crypto analysis."""
        keygens = []
        
        crypto_operations = license_analysis.get('crypto_operations', [])
        
        for crypto_op in crypto_operations:
            algorithm = crypto_op.get('algorithm', '')
            purpose = crypto_op.get('purpose', '')
            
            if purpose == 'key_validation':
                keygen = {
                    'algorithm': algorithm,
                    'implementation': self._generate_keygen_implementation(crypto_op),
                    'success_probability': self._assess_keygen_feasibility(crypto_op),
                    'complexity': 'high' if 'RSA' in algorithm or 'AES' in algorithm else 'medium'
                }
                keygens.append(keygen)

        return keygens

    def _generate_registry_modifications(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate registry modification instructions."""
        modifications = []
        
        registry_ops = license_analysis.get('registry_operations', [])
        
        for reg_op in registry_ops:
            modifications.append({
                'operation': 'create_key',
                'registry_path': self._predict_registry_path(reg_op),
                'value_name': 'License',
                'value_data': self._generate_license_value(),
                'value_type': 'REG_SZ',
                'description': 'Create fake license registry entry'
            })

        return modifications

    def _generate_file_modifications(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate file modification instructions."""
        modifications = []
        
        file_ops = license_analysis.get('file_operations', [])
        
        for file_op in file_ops:
            modifications.append({
                'operation': 'create_file',
                'file_path': self._predict_license_file_path(file_op),
                'content': self._generate_license_file_content(),
                'description': 'Create fake license file'
            })

        return modifications

    def _generate_memory_patches(self, r2, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate runtime memory patches."""
        patches = []
        
        validation_functions = license_analysis.get('validation_functions', [])
        
        for func_info in validation_functions:
            func_addr = func_info['function'].get('offset', 0)
            
            if func_addr:
                patches.append({
                    'type': 'memory_patch',
                    'address': hex(func_addr),
                    'original_bytes': self._get_original_bytes(r2, func_addr),
                    'patch_bytes': self._generate_patch_bytes(func_info),
                    'description': f'Runtime patch for {func_info["function"]["name"]}'
                })

        return patches

    def _generate_api_hooks(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate API hook implementations."""
        hooks = []
        
        # Registry API hooks
        registry_ops = license_analysis.get('registry_operations', [])
        for reg_op in registry_ops:
            hooks.append({
                'api': reg_op['api']['name'],
                'hook_type': 'registry_redirect',
                'implementation': self._generate_registry_hook_code(reg_op),
                'description': 'Hook registry access for license validation'
            })

        # File API hooks
        file_ops = license_analysis.get('file_operations', [])
        for file_op in file_ops:
            hooks.append({
                'api': file_op['api']['name'],
                'hook_type': 'file_redirect',
                'implementation': self._generate_file_hook_code(file_op),
                'description': 'Hook file access for license validation'
            })

        return hooks

    def _generate_validation_bypasses(self, license_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate validation bypass techniques."""
        bypasses = []
        
        validation_flow = license_analysis.get('validation_flow', [])
        
        for step in validation_flow:
            bypass = {
                'target': step['function'],
                'method': step['recommended_approach'],
                'difficulty': step['bypass_difficulty'],
                'implementation_steps': self._generate_bypass_steps(step),
                'tools_required': self._get_required_tools(step),
                'success_indicators': self._get_success_indicators(step)
            }
            bypasses.append(bypass)

        return bypasses

    # Helper methods for implementation generation
    def _suggest_bypass_method(self, pattern: Dict[str, Any]) -> str:
        """Suggest bypass method for a validation pattern."""
        line = pattern.get('line', '').lower()
        
        if 'if' in line and ('valid' in line or 'check' in line):
            return 'nop_conditional'
        elif 'return' in line:
            return 'force_return_true'
        elif 'jump' in line or 'jmp' in line:
            return 'modify_jump_target'
        else:
            return 'nop_instruction'

    def _identify_crypto_algorithm(self, operation: str) -> str:
        """Identify cryptographic algorithm from operation name."""
        op_lower = operation.lower()
        
        if 'aes' in op_lower:
            return 'AES'
        elif 'des' in op_lower:
            return 'DES'
        elif 'rsa' in op_lower:
            return 'RSA'
        elif 'sha' in op_lower:
            return 'SHA'
        elif 'md5' in op_lower:
            return 'MD5'
        else:
            return 'Unknown'

    def _identify_crypto_purpose(self, line: str) -> str:
        """Identify purpose of cryptographic operation."""
        line_lower = line.lower()
        
        if any(keyword in line_lower for keyword in ['key', 'serial', 'license']):
            return 'key_validation'
        elif any(keyword in line_lower for keyword in ['hash', 'digest']):
            return 'integrity_check'
        elif any(keyword in line_lower for keyword in ['encrypt', 'decrypt']):
            return 'data_protection'
        else:
            return 'unknown'

    def _assess_string_bypass_potential(self, string_content: str) -> str:
        """Assess bypass potential for license string."""
        content_lower = string_content.lower()
        
        if any(keyword in content_lower for keyword in ['invalid', 'expired', 'trial']):
            return 'high'  # Error messages can be easily patched
        elif any(keyword in content_lower for keyword in ['valid', 'registered', 'licensed']):
            return 'medium'  # Success messages
        else:
            return 'low'

    def _assess_bypass_difficulty(self, func_info: Dict[str, Any]) -> str:
        """Assess bypass difficulty for function."""
        complexity = func_info.get('complexity', 'low')
        validation_type = func_info.get('validation_type', 'simple')
        
        if validation_type == 'cryptographic' and complexity == 'high':
            return 'hard'
        elif validation_type == 'online' or complexity == 'high':
            return 'medium'
        else:
            return 'easy'

    def _recommend_bypass_approach(self, func_info: Dict[str, Any]) -> str:
        """Recommend bypass approach for function."""
        validation_type = func_info.get('validation_type', 'simple')
        
        approach_map = {
            'simple': 'direct_patching',
            'cryptographic': 'crypto_bypass',
            'online': 'network_interception',
            'time_based': 'time_manipulation',
            'hardware_fingerprint': 'hardware_spoofing'
        }
        
        return approach_map.get(validation_type, 'direct_patching')

    def _generate_direct_patch_implementation(self, func_info: Dict[str, Any]) -> Dict[str, str]:
        """Generate direct patch implementation."""
        return {
            'method': 'binary_patch',
            'target': func_info['function']['name'],
            'patch_type': 'nop_validation',
            'instructions': 'Replace validation checks with NOP instructions',
            'tools': 'Hex editor or debugger'
        }

    def _generate_crypto_bypass_implementation(self, func_info: Dict[str, Any]) -> Dict[str, str]:
        """Generate crypto bypass implementation."""
        return {
            'method': 'crypto_bypass',
            'target': func_info['function']['name'],
            'patch_type': 'skip_crypto_validation',
            'instructions': 'Patch crypto validation to always succeed',
            'tools': 'Disassembler and hex editor'
        }

    def _generate_network_bypass_implementation(self, func_info: Dict[str, Any]) -> Dict[str, str]:
        """Generate network bypass implementation."""
        return {
            'method': 'network_interception',
            'target': func_info['function']['name'],
            'patch_type': 'mock_server_response',
            'instructions': 'Intercept network calls and provide fake success response',
            'tools': 'Proxy server or API hooking'
        }

    def _generate_time_bypass_implementation(self, func_info: Dict[str, Any]) -> Dict[str, str]:
        """Generate time bypass implementation."""
        return {
            'method': 'time_manipulation',
            'target': func_info['function']['name'],
            'patch_type': 'system_time_hook',
            'instructions': 'Hook time functions to return fixed date',
            'tools': 'API hooking or system time manipulation'
        }

    def _generate_registry_bypass_implementation(self, license_analysis: Dict[str, Any]) -> Dict[str, str]:
        """Generate registry bypass implementation."""
        return {
            'method': 'registry_manipulation',
            'target': 'Registry operations',
            'patch_type': 'registry_redirection',
            'instructions': 'Create fake registry entries or redirect registry access',
            'tools': 'Registry editor or API hooking'
        }

    def _create_binary_patch(self, r2, func_info: Dict[str, Any], bypass_point: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create binary patch for bypass point."""
        func_addr = func_info['function'].get('offset', 0)
        if not func_addr:
            return None

        try:
            # Get function disassembly
            disasm = r2._execute_command(f'pdf @ {hex(func_addr)}')
            
            # Find the target instruction
            target_line = bypass_point.get('line_number', 0)
            bypass_method = bypass_point.get('bypass_method', 'nop_instruction')
            
            patch = {
                'function': func_info['function']['name'],
                'address': hex(func_addr),
                'target_line': target_line,
                'bypass_method': bypass_method,
                'patch_description': f'Patch {bypass_method} at line {target_line}',
                'original_instruction': bypass_point.get('instruction', ''),
                'patch_instruction': self._generate_patch_instruction(bypass_method),
                'patch_bytes': self._generate_patch_bytes_for_method(bypass_method)
            }
            
            return patch
            
        except R2Exception:
            return None

    def _generate_keygen_implementation(self, crypto_op: Dict[str, Any]) -> Dict[str, str]:
        """Generate keygen implementation."""
        algorithm = crypto_op.get('algorithm', 'Unknown')
        
        if algorithm == 'MD5' or algorithm == 'SHA':
            return {
                'type': 'hash_based_keygen',
                'algorithm': algorithm,
                'implementation': f'Generate keys using {algorithm} hash of hardware ID',
                'code_template': self._get_hash_keygen_template(algorithm)
            }
        elif algorithm == 'AES':
            return {
                'type': 'symmetric_keygen',
                'algorithm': algorithm,
                'implementation': 'Reverse engineer AES key derivation',
                'code_template': self._get_aes_keygen_template()
            }
        else:
            return {
                'type': 'generic_keygen',
                'algorithm': algorithm,
                'implementation': 'Generic key generation based on observed patterns',
                'code_template': self._get_generic_keygen_template()
            }

    def _assess_keygen_feasibility(self, crypto_op: Dict[str, Any]) -> float:
        """Assess feasibility of keygen creation."""
        algorithm = crypto_op.get('algorithm', 'Unknown')
        
        if algorithm in ['MD5', 'SHA', 'CRC32']:
            return 0.8  # Hash-based systems are often reversible
        elif algorithm in ['AES', 'DES']:
            return 0.5  # Symmetric encryption can be challenging
        elif algorithm in ['RSA']:
            return 0.2  # Asymmetric encryption is very difficult
        else:
            return 0.3  # Unknown algorithms

    def _predict_registry_path(self, reg_op: Dict[str, Any]) -> str:
        """Predict registry path for license storage."""
        # Common license registry paths
        common_paths = [
            r'HKEY_CURRENT_USER\Software\{AppName}\License',
            r'HKEY_LOCAL_MACHINE\Software\{AppName}\Registration',
            r'HKEY_CURRENT_USER\Software\{AppName}\Serial'
        ]
        return common_paths[0]  # Return most common

    def _generate_license_value(self) -> str:
        """Generate fake license value."""
        import random
        import string
        
        # Generate realistic license key format
        segments = []
        for _ in range(4):
            segment = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            segments.append(segment)
        
        return '-'.join(segments)

    def _predict_license_file_path(self, file_op: Dict[str, Any]) -> str:
        """Predict license file path."""
        common_paths = [
            'license.dat',
            'registration.key',
            'license.lic',
            'serial.txt'
        ]
        return common_paths[0]

    def _generate_license_file_content(self) -> str:
        """Generate fake license file content."""
        return f"""# License File
Licensed=1
Serial={self._generate_license_value()}
Expires=2099-12-31
Valid=True"""

    def _get_original_bytes(self, r2, func_addr: int) -> str:
        """Get original bytes at function address."""
        try:
            # Get first few bytes of function
            bytes_data = r2._execute_command(f'p8 16 @ {hex(func_addr)}')
            return bytes_data.strip() if bytes_data else '00' * 16
        except R2Exception:
            return '00' * 16

    def _generate_patch_bytes(self, func_info: Dict[str, Any]) -> str:
        """Generate patch bytes for function."""
        # Simple patch: replace first instruction with return 1 (mov eax, 1; ret)
        # This is architecture-specific, simplified for x86
        return 'b8010000c3'  # mov eax, 1; ret

    def _generate_registry_hook_code(self, reg_op: Dict[str, Any]) -> str:
        """Generate registry hook code."""
        return '''
// Registry Hook Implementation
LONG WINAPI HookedRegQueryValueEx(HKEY hKey, LPCSTR lpValueName, ...) {
    if (strstr(lpValueName, "License") || strstr(lpValueName, "Serial")) {
        // Return fake license data
        strcpy(lpData, "VALID-LICENSE-KEY");
        return ERROR_SUCCESS;
    }
    return OriginalRegQueryValueEx(hKey, lpValueName, ...);
}'''

    def _generate_file_hook_code(self, file_op: Dict[str, Any]) -> str:
        """Generate file hook code."""
        return '''
// File Hook Implementation
HANDLE WINAPI HookedCreateFile(LPCSTR lpFileName, ...) {
    if (strstr(lpFileName, "license") || strstr(lpFileName, ".lic")) {
        // Redirect to fake license file
        return OriginalCreateFile("fake_license.dat", ...);
    }
    return OriginalCreateFile(lpFileName, ...);
}'''

    def _generate_bypass_steps(self, step: Dict[str, Any]) -> List[str]:
        """Generate step-by-step bypass instructions."""
        method = step.get('recommended_approach', 'direct_patching')
        
        if method == 'direct_patching':
            return [
                '1. Open binary in hex editor',
                '2. Locate validation function',
                '3. Replace validation check with NOP or success return',
                '4. Save patched binary',
                '5. Test bypass'
            ]
        elif method == 'crypto_bypass':
            return [
                '1. Analyze cryptographic validation',
                '2. Identify crypto algorithm and key',
                '3. Patch crypto validation to skip verification',
                '4. Test with various inputs',
                '5. Generate keygen if possible'
            ]
        else:
            return [
                '1. Analyze validation mechanism',
                '2. Identify bypass points',
                '3. Implement bypass',
                '4. Test bypass',
                '5. Document method'
            ]

    def _get_required_tools(self, step: Dict[str, Any]) -> List[str]:
        """Get required tools for bypass."""
        method = step.get('recommended_approach', 'direct_patching')
        
        tool_map = {
            'direct_patching': ['Hex Editor', 'Disassembler', 'Debugger'],
            'crypto_bypass': ['Disassembler', 'Crypto Analysis Tools', 'Debugger'],
            'network_interception': ['Proxy Server', 'Network Monitor', 'API Hooking Tool'],
            'time_manipulation': ['API Hooking Tool', 'System Time Manipulation'],
            'hardware_spoofing': ['Hardware ID Spoofer', 'API Hooking Tool']
        }
        
        return tool_map.get(method, ['Disassembler', 'Hex Editor'])

    def _get_success_indicators(self, step: Dict[str, Any]) -> List[str]:
        """Get success indicators for bypass."""
        return [
            'Application launches without license prompt',
            'Full functionality available',
            'No trial limitations',
            'No expiration warnings',
            'Professional/registered version features accessible'
        ]

    def _generate_patch_instruction(self, bypass_method: str) -> str:
        """Generate patch instruction based on method."""
        instruction_map = {
            'nop_conditional': 'NOP',
            'force_return_true': 'MOV EAX, 1; RET',
            'modify_jump_target': 'JMP success_label',
            'nop_instruction': 'NOP'
        }
        return instruction_map.get(bypass_method, 'NOP')

    def _generate_patch_bytes_for_method(self, bypass_method: str) -> str:
        """Generate patch bytes for specific method."""
        # Simplified x86 opcodes
        byte_map = {
            'nop_conditional': '90',  # NOP
            'force_return_true': 'b801000000c3',  # mov eax, 1; ret
            'modify_jump_target': 'eb??',  # jmp rel8 (offset calculated at runtime)
            'nop_instruction': '90'  # NOP
        }
        return byte_map.get(bypass_method, '90')

    def _get_hash_keygen_template(self, algorithm: str) -> str:
        """Get hash-based keygen template."""
        return f'''
# {algorithm} Keygen Template
import hashlib

def generate_key(hardware_id):
    # Create hash of hardware ID
    hash_obj = hashlib.{algorithm.lower()}()
    hash_obj.update(hardware_id.encode())
    
    # Format as license key
    raw_hash = hash_obj.hexdigest()
    formatted_key = '-'.join([raw_hash[i:i+4].upper() for i in range(0, 16, 4)])
    
    return formatted_key
'''

    def _get_aes_keygen_template(self) -> str:
        """Get AES keygen template."""
        return '''
# AES Keygen Template
from Crypto.Cipher import AES
import hashlib

def generate_key(user_info):
    # Derive AES key from user information
    key_material = f"{user_info}SALT".encode()
    key = hashlib.sha256(key_material).digest()[:16]
    
    # Encrypt license data
    cipher = AES.new(key, AES.MODE_ECB)
    license_data = b"VALID_LICENSE_12"
    encrypted = cipher.encrypt(license_data)
    
    return encrypted.hex().upper()
'''

    def _get_generic_keygen_template(self) -> str:
        """Get generic keygen template."""
        return '''
# Generic Keygen Template
import random
import string

def generate_key():
    # Generate random license key
    segments = []
    for _ in range(4):
        segment = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
        segments.append(segment)
    
    return '-'.join(segments)
'''

    def _calculate_success_probabilities(self, result: Dict[str, Any]) -> Dict[str, float]:
        """Calculate success probabilities for different approaches."""
        probabilities = {}
        
        strategies = result.get('bypass_strategies', [])
        
        for strategy in strategies:
            strategy_name = strategy.get('strategy', 'unknown')
            success_rate = strategy.get('success_rate', 0.5)
            probabilities[strategy_name] = success_rate
        
        # Calculate overall success probability
        if probabilities:
            probabilities['overall'] = max(probabilities.values())
        
        return probabilities

    def _generate_implementation_guide(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive implementation guide."""
        guide = {
            'recommended_approach': '',
            'step_by_step_guide': [],
            'tools_needed': [],
            'estimated_time': '',
            'difficulty_level': '',
            'success_probability': 0.0,
            'alternative_methods': []
        }

        strategies = result.get('bypass_strategies', [])
        
        if strategies:
            # Recommend strategy with highest success rate
            best_strategy = max(strategies, key=lambda x: x.get('success_rate', 0))
            
            guide['recommended_approach'] = best_strategy.get('strategy', 'Unknown')
            guide['step_by_step_guide'] = best_strategy.get('implementation', {}).get('instructions', '').split('. ')
            guide['tools_needed'] = [best_strategy.get('implementation', {}).get('tools', '')]
            guide['difficulty_level'] = best_strategy.get('difficulty', 'medium')
            guide['success_probability'] = best_strategy.get('success_rate', 0.5)
            
            # Add alternative methods
            guide['alternative_methods'] = [
                {
                    'method': s.get('strategy', ''),
                    'success_rate': s.get('success_rate', 0),
                    'difficulty': s.get('difficulty', 'medium')
                }
                for s in strategies if s != best_strategy
            ]

        return guide

    def _assess_bypass_risks(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risks associated with bypass methods."""
        return {
            'legal_risks': [
                'Software license violation',
                'Copyright infringement',
                'Terms of service violation'
            ],
            'technical_risks': [
                'Binary corruption',
                'Application instability',
                'Detection by anti-tamper mechanisms'
            ],
            'detection_risks': [
                'Signature-based detection',
                'Behavioral analysis detection',
                'Online validation bypass detection'
            ],
            'mitigation_strategies': [
                'Use virtual machines for testing',
                'Backup original binary',
                'Test thoroughly before deployment',
                'Use stealthy patching techniques'
            ]
        }


def generate_license_bypass(binary_path: str, radare2_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate comprehensive license bypass for a binary.
    
    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        
    Returns:
        Complete bypass generation results
    """
    generator = R2BypassGenerator(binary_path, radare2_path)
    return generator.generate_comprehensive_bypass()


__all__ = ['R2BypassGenerator', 'generate_license_bypass']