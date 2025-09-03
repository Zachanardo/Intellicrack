"""Phase 2 Cross-Validation Engine for Intellicrack Validation System.

This module implements comprehensive cross-validation using multiple independent
protection scanners and validation methods to provide undeniable evidence of
detection accuracy and prevent false positives.

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

import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    yara = None

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

# Import Intellicrack modules
try:
    from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
    from intellicrack.utils.logger import get_logger
    HAS_INTELLICRACK_MODULES = True
except ImportError:
    HAS_INTELLICRACK_MODULES = False


class ValidationResult:
    """Container for cross-validation results."""

    def __init__(self, binary_path: Path):
        """Initialize validation result.

        Args:
            binary_path: Path to analyzed binary
        """
        self.binary_path = binary_path
        self.timestamp = time.time()

        # Scanner results
        self.peid_results: List[Dict[str, Any]] = []
        self.die_results: List[Dict[str, Any]] = []
        self.protid_results: List[Dict[str, Any]] = []
        self.yara_results: List[Dict[str, Any]] = []

        # Consensus analysis
        self.consensus_score: float = 0.0
        self.agreed_protections: List[str] = []
        self.conflicting_results: List[Dict[str, Any]] = []

        # Validation metadata
        self.validation_sources: List[str] = []
        self.confidence_level: float = 0.0


class CrossValidation:
    """Cross-validation engine using multiple protection scanners.

    This class coordinates multiple independent protection detection tools
    to validate Intellicrack's detection results and prevent false positives.
    """

    def __init__(self, scanner_dir: Path, logger: Optional[logging.Logger] = None):
        """Initialize cross-validation engine.

        Args:
            scanner_dir: Directory containing protection scanner tools
            logger: Optional logger instance
        """
        self.scanner_dir = Path(scanner_dir)
        self.logger = logger or get_logger(__name__)

        # Validate dependencies
        self._validate_dependencies()

        # Initialize scanner paths
        self._initialize_scanner_paths()

        # Initialize YARA engine
        if HAS_INTELLICRACK_MODULES:
            self.yara_engine = YaraPatternEngine()
        else:
            self.yara_engine = None

    def _validate_dependencies(self) -> None:
        """Validate required dependencies are available."""
        missing_deps = []

        if not HAS_YARA:
            missing_deps.append("yara-python")
        if not HAS_REQUESTS:
            missing_deps.append("requests")

        if missing_deps:
            self.logger.warning(
                f"Optional dependencies missing: {', '.join(missing_deps)}. "
                "Some validation methods may be unavailable."
            )

    def _initialize_scanner_paths(self) -> None:
        """Initialize paths to protection scanner executables."""
        self.scanner_paths = {
            'peid': self.scanner_dir / 'peid.exe',
            'die': self.scanner_dir / 'die.exe',  # Detect It Easy
            'protid': self.scanner_dir / 'protectionid.exe',
            'exeinfope': self.scanner_dir / 'exeinfope.exe'
        }

        # Check which scanners are available
        self.available_scanners = []
        for scanner, path in self.scanner_paths.items():
            if path.exists():
                self.available_scanners.append(scanner)
                self.logger.info(f"Found scanner: {scanner} at {path}")
            else:
                self.logger.warning(f"Scanner not found: {scanner} at {path}")

        if not self.available_scanners:
            self.logger.error("No protection scanners found in scanner directory")

    def run_peid_analysis(self, binary_path: Path) -> List[Dict[str, Any]]:
        """Run PEiD protection scanner analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            List of PEiD detection results
        """
        if 'peid' not in self.available_scanners:
            self.logger.warning("PEiD scanner not available")
            return []

        self.logger.info(f"Running PEiD analysis on {binary_path}")

        try:
            peid_path = self.scanner_paths['peid']

            # Run PEiD analysis with fallback detection methods
            cmd = [str(peid_path), str(binary_path)]

            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            # Parse PEiD output (format varies by tool)
            peid_results = self._parse_peid_output(result.stdout)

            self.logger.info(f"PEiD found {len(peid_results)} protections")
            return peid_results

        except subprocess.TimeoutExpired:
            self.logger.error("PEiD analysis timed out")
            return []
        except Exception as e:
            self.logger.error(f"PEiD analysis failed: {e}")
            return []

    def _parse_peid_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse PEiD scanner output with version extraction.

        Args:
            output: Raw output from PEiD

        Returns:
            Parsed protection detection results with version information
        """
        results = []

        # PEiD output parsing (example format)
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Look for protection signatures
            if '->' in line or 'detected:' in line.lower():
                parts = line.split('->' if '->' in line else 'detected:')
                if len(parts) >= 2:
                    protection_info = parts[1].strip()
                    confidence = 0.8  # Default confidence for PEiD

                    # Extract confidence if present
                    if '[' in protection_info and ']' in protection_info:
                        conf_start = protection_info.find('[')
                        conf_end = protection_info.find(']')
                        conf_str = protection_info[conf_start+1:conf_end]
                        try:
                            confidence = float(conf_str) / 100.0
                        except ValueError:
                            pass
                        protection_info = protection_info[:conf_start].strip()

                    # Extract version information from protection name
                    protection_name = protection_info
                    version = ''

                    # Look for version patterns: v1.0, 1.0, (v1.0), etc.
                    import re

                    # Pattern 1: v followed by version number
                    version_match = re.search(r'\bv(\d+(?:\.\d+)*(?:\.\d+)?)\b', protection_info, re.IGNORECASE)
                    if version_match:
                        version = 'v' + version_match.group(1)
                        protection_name = re.sub(r'\s*\bv\d+(?:\.\d+)*(?:\.\d+)?\b\s*', ' ', protection_info, flags=re.IGNORECASE).strip()
                    else:
                        # Pattern 2: standalone version number after space
                        version_match = re.search(r'\s+(\d+(?:\.\d+)+)\s*$', protection_info)
                        if version_match:
                            version = version_match.group(1)
                            protection_name = protection_info[:version_match.start()].strip()
                        else:
                            # Pattern 3: version in parentheses
                            version_match = re.search(r'\(([vV]?\d+(?:\.\d+)*(?:\.\d+)?)\)', protection_info)
                            if version_match:
                                version = version_match.group(1)
                                protection_name = re.sub(r'\s*\([vV]?\d+(?:\.\d+)*(?:\.\d+)?\)\s*', ' ', protection_info).strip()

                    # Clean up protection name
                    protection_name = ' '.join(protection_name.split())

                    results.append({
                        'scanner': 'peid',
                        'protection': protection_name,
                        'version': version,
                        'confidence': confidence,
                        'raw_output': line,
                        'timestamp': time.time()
                    })

        return results

    def run_die_analysis(self, binary_path: Path) -> List[Dict[str, Any]]:
        """Run Detect It Easy (DIE) protection scanner analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            List of DIE detection results
        """
        if 'die' not in self.available_scanners:
            self.logger.warning("DIE scanner not available")
            return []

        self.logger.info(f"Running DIE analysis on {binary_path}")

        try:
            die_path = self.scanner_paths['die']

            # Run DIE with JSON output for easier parsing
            cmd = [str(die_path), '-j', str(binary_path)]

            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            # Parse DIE JSON output
            die_results = self._parse_die_output(result.stdout)

            self.logger.info(f"DIE found {len(die_results)} protections")
            return die_results

        except subprocess.TimeoutExpired:
            self.logger.error("DIE analysis timed out")
            return []
        except Exception as e:
            self.logger.error(f"DIE analysis failed: {e}")
            return []

    def _parse_die_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Detect It Easy output.

        Args:
            output: Raw output from DIE

        Returns:
            Parsed protection detection results
        """
        results = []

        try:
            # Try to parse as JSON first
            if output.strip().startswith('{'):
                data = json.loads(output)

                # Extract protection information from DIE JSON
                if 'detects' in data:
                    for detect in data['detects']:
                        results.append({
                            'scanner': 'die',
                            'protection': detect.get('name', 'unknown'),
                            'version': detect.get('version', ''),
                            'confidence': detect.get('confidence', 0.5),
                            'type': detect.get('type', ''),
                            'raw_output': str(detect),
                            'timestamp': time.time()
                        })

            else:
                # Parse text output
                for line in output.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Look for protection indicators
                    if any(keyword in line.lower() for keyword in
                           ['packer:', 'protector:', 'compiler:', 'linker:']):

                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            category = parts[0].strip()
                            protection = parts[1].strip()

                            results.append({
                                'scanner': 'die',
                                'protection': protection,
                                'category': category,
                                'confidence': 0.7,
                                'raw_output': line,
                                'timestamp': time.time()
                            })

        except json.JSONDecodeError:
            self.logger.debug("DIE output is not valid JSON, using text parsing")
        except Exception as e:
            self.logger.error(f"Error parsing DIE output: {e}")

        return results

    def run_protid_analysis(self, binary_path: Path) -> List[Dict[str, Any]]:
        """Run Protection ID scanner analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            List of Protection ID detection results
        """
        if 'protid' not in self.available_scanners:
            self.logger.warning("Protection ID scanner not available")
            return []

        self.logger.info(f"Running Protection ID analysis on {binary_path}")

        try:
            protid_path = self.scanner_paths['protid']

            # Run Protection ID scanner
            cmd = [str(protid_path), str(binary_path)]

            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            # Parse Protection ID output
            protid_results = self._parse_protid_output(result.stdout)

            self.logger.info(f"Protection ID found {len(protid_results)} protections")
            return protid_results

        except subprocess.TimeoutExpired:
            self.logger.error("Protection ID analysis timed out")
            return []
        except Exception as e:
            self.logger.error(f"Protection ID analysis failed: {e}")
            return []

    def _parse_protid_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Protection ID scanner output.

        Args:
            output: Raw output from Protection ID

        Returns:
            Parsed protection detection results
        """
        results = []

        # Protection ID output parsing
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Look for protection detection lines
            if 'detected:' in line.lower() or '->' in line:
                parts = line.split('detected:' if 'detected:' in line.lower() else '->')
                if len(parts) >= 2:
                    protection_name = parts[1].strip()

                    # Extract version if present
                    version = ''
                    if 'v' in protection_name:
                        version_parts = protection_name.split('v')
                        if len(version_parts) > 1:
                            version = 'v' + version_parts[1].split()[0]
                            protection_name = version_parts[0].strip()

                    results.append({
                        'scanner': 'protid',
                        'protection': protection_name,
                        'version': version,
                        'confidence': 0.75,
                        'raw_output': line,
                        'timestamp': time.time()
                    })

        return results

    def run_yara_validation(self, binary_path: Path) -> List[Dict[str, Any]]:
        """Run YARA rule validation for licensing protection patterns.

        Args:
            binary_path: Path to binary file

        Returns:
            List of YARA detection results
        """
        if not HAS_YARA:
            self.logger.warning("YARA not available for validation")
            return []

        self.logger.info(f"Running YARA validation on {binary_path}")

        yara_results = []

        try:
            # Use Intellicrack's YARA engine if available
            if self.yara_engine:
                results = self.yara_engine.scan_binary(binary_path)
                for result in results:
                    yara_results.append({
                        'scanner': 'yara',
                        'rule': result.get('rule'),
                        'matches': result.get('matches', []),
                        'confidence': 0.8,
                        'timestamp': time.time()
                    })
            else:
                # Run YARA directly with custom rules
                yara_results = self._run_custom_yara_rules(binary_path)

            self.logger.info(f"YARA found {len(yara_results)} matches")
            return yara_results

        except Exception as e:
            self.logger.error(f"YARA validation failed: {e}")
            return []

    def _run_custom_yara_rules(self, binary_path: Path) -> List[Dict[str, Any]]:
        """Run custom YARA rules for protection detection.

        Args:
            binary_path: Path to binary file

        Returns:
            YARA detection results
        """
        # Define protection-specific YARA rules
        protection_rules = {
            'flexlm_detection': '''
rule FlexLM_Protection {
    strings:
        $a = "FLEXlm" nocase
        $b = "lm_checkout" nocase
        $c = "lm_checkin" nocase
        $d = "FLEXLM_TIMEOUT" nocase
        $e = { 46 4C 45 58 6C 6D }
    condition:
        any of them
}
            ''',
            'adobe_detection': '''
rule Adobe_Licensing {
    strings:
        $a = "Adobe" nocase
        $b = "amtlib" nocase
        $c = "oobe" nocase
        $d = "activation" nocase
        $e = "AdobeActivation" nocase
    condition:
        any of them
}
            ''',
            'hasp_detection': '''
rule HASP_Sentinel {
    strings:
        $a = "HASP" nocase
        $b = "Sentinel" nocase
        $c = "Rainbow Technologies" nocase
        $d = "dongle" nocase
        $e = { 48 41 53 50 }
    condition:
        any of them
}
            '''
        }

        results = []

        try:
            for _rule_name, rule_text in protection_rules.items():
                # Compile and run YARA rule
                compiled_rule = yara.compile(source=rule_text)
                matches = compiled_rule.match(str(binary_path))

                for match in matches:
                    results.append({
                        'scanner': 'yara',
                        'rule': match.rule,
                        'strings': [str(s) for s in match.strings],
                        'confidence': 0.9,
                        'timestamp': time.time()
                    })

        except Exception as e:
            self.logger.error(f"Custom YARA rules failed: {e}")

        return results

    def validate_against_signatures(
        self,
        binary_path: Path,
        known_signatures: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Validate against known protection signatures and byte patterns.

        Args:
            binary_path: Path to binary file
            known_signatures: List of known protection signatures

        Returns:
            Signature validation results
        """
        self.logger.info(f"Validating against {len(known_signatures)} known signatures")

        validation_results = []

        try:
            # Read binary data
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            for sig in known_signatures:
                sig_name = sig.get('name', 'unknown')
                pattern = sig.get('pattern', '')

                if not pattern:
                    continue

                # Convert hex pattern to bytes
                try:
                    if isinstance(pattern, str):
                        pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
                    else:
                        pattern_bytes = pattern

                    # Search for pattern in binary
                    offset = binary_data.find(pattern_bytes)

                    if offset != -1:
                        validation_results.append({
                            'scanner': 'signature_validation',
                            'signature_name': sig_name,
                            'offset': hex(offset),
                            'pattern': pattern,
                            'confidence': sig.get('confidence', 0.8),
                            'timestamp': time.time()
                        })

                        self.logger.info(f"Found signature {sig_name} at offset {hex(offset)}")

                except Exception as e:
                    self.logger.debug(f"Error processing signature {sig_name}: {e}")
                    continue

            return validation_results

        except Exception as e:
            self.logger.error(f"Signature validation failed: {e}")
            return []

    def compare_with_vendor_docs(
        self,
        detected_protection: str,
        vendor_specs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Compare detection results with vendor SDK samples and documentation.

        Args:
            detected_protection: Name of detected protection
            vendor_specs: Vendor documentation and specifications

        Returns:
            Comparison results with confidence score
        """
        self.logger.info(f"Comparing {detected_protection} with vendor documentation")

        comparison_result = {
            'protection': detected_protection,
            'vendor_match': False,
            'confidence': 0.0,
            'matching_criteria': [],
            'discrepancies': [],
            'timestamp': time.time()
        }

        try:
            # Get expected characteristics from vendor specs
            expected_name = vendor_specs.get('official_name', '').lower()
            expected_version = vendor_specs.get('version', '')
            expected_signatures = vendor_specs.get('signatures', [])
            vendor_specs.get('apis', [])

            # Compare protection name
            detected_lower = detected_protection.lower()
            if expected_name in detected_lower or detected_lower in expected_name:
                comparison_result['matching_criteria'].append('name_match')
                comparison_result['confidence'] += 0.3

            # Compare version if available
            if expected_version and expected_version in detected_protection:
                comparison_result['matching_criteria'].append('version_match')
                comparison_result['confidence'] += 0.2

            # Compare signatures
            matching_sigs = 0
            for sig in expected_signatures:
                if self._signature_matches(sig):
                    matching_sigs += 1

            if matching_sigs > 0:
                comparison_result['matching_criteria'].append(f'signature_matches_{matching_sigs}')
                comparison_result['confidence'] += min(0.4, matching_sigs * 0.1)

            # Set vendor match if confidence is high enough
            if comparison_result['confidence'] >= 0.7:
                comparison_result['vendor_match'] = True

            return comparison_result

        except Exception as e:
            self.logger.error(f"Vendor comparison failed: {e}")
            return comparison_result

    def _signature_matches(self, signature: Dict[str, Any]) -> bool:
        """Check if a signature matches current binary using comprehensive pattern matching.

        Args:
            signature: Signature to check containing hex patterns, offsets, and metadata

        Returns:
            True if signature matches
        """
        try:
            # Check for required signature components
            if not signature.get('hex_pattern') or not hasattr(self, 'current_binary_data'):
                return False

            hex_pattern = signature.get('hex_pattern', '')
            offset = signature.get('offset', 0)
            mask = signature.get('mask', 'x' * (len(hex_pattern) // 2))

            # Convert hex pattern to bytes
            if isinstance(hex_pattern, str):
                # Handle wildcard patterns (? for unknown bytes)
                pattern_bytes = bytearray()
                mask_bytes = bytearray()

                hex_clean = hex_pattern.replace('?', '00').replace(' ', '')
                for i in range(0, len(hex_clean), 2):
                    if i + 1 < len(hex_clean):
                        byte_str = hex_clean[i:i+2]
                        pattern_bytes.append(int(byte_str, 16))

                        # Check if original had wildcard
                        original_byte = hex_pattern[i:i+2] if i < len(hex_pattern) else '??'
                        mask_bytes.append(0xFF if '?' not in original_byte else 0x00)
            else:
                return False

            # Search for pattern in binary data with mask
            if hasattr(self, 'current_binary_data') and self.current_binary_data:
                return self._search_pattern_with_mask(
                    self.current_binary_data,
                    pattern_bytes,
                    mask_bytes,
                    offset
                )

        except Exception as e:
            self.logger.debug(f"Signature matching error: {e}")

        return False

    def _search_pattern_with_mask(self, data: bytes, pattern: bytearray, mask: bytearray, start_offset: int = 0) -> bool:
        """Search for pattern in data using byte mask."""
        if len(pattern) != len(mask) or len(pattern) == 0:
            return False

        search_end = len(data) - len(pattern) + 1
        if start_offset >= search_end:
            return False

        for i in range(start_offset, search_end):
            match_found = True
            for j, (pattern_byte, mask_byte) in enumerate(zip(pattern, mask, strict=False)):
                if mask_byte != 0 and (data[i + j] & mask_byte) != (pattern_byte & mask_byte):
                    match_found = False
                    break

            if match_found:
                return True

        return False

    def validate_behavioral_patterns(
        self,
        binary_path: Path,
        expected_behaviors: List[str]
    ) -> Dict[str, Any]:
        """Validate behavioral patterns (license checks, server communication, etc.).

        Args:
            binary_path: Path to binary file
            expected_behaviors: List of expected behavioral patterns

        Returns:
            Behavioral validation results
        """
        self.logger.info(f"Validating behavioral patterns for {binary_path}")

        behavior_results = {
            'license_checks': False,
            'server_communication': False,
            'file_access_patterns': False,
            'registry_access': False,
            'api_patterns': [],
            'confidence': 0.0,
            'timestamp': time.time()
        }

        try:
            # Analyze imports for behavioral indicators
            import_patterns = self._analyze_behavioral_imports(binary_path)
            behavior_results.update(import_patterns)

            # Analyze strings for behavioral indicators
            string_patterns = self._analyze_behavioral_strings(binary_path)
            behavior_results.update(string_patterns)

            # Calculate overall confidence
            matched_behaviors = sum([
                behavior_results['license_checks'],
                behavior_results['server_communication'],
                behavior_results['file_access_patterns'],
                behavior_results['registry_access']
            ])

            behavior_results['confidence'] = matched_behaviors / 4.0

            return behavior_results

        except Exception as e:
            self.logger.error(f"Behavioral validation failed: {e}")
            return behavior_results

    def _analyze_behavioral_imports(self, binary_path: Path) -> Dict[str, Any]:
        """Analyze imports for behavioral patterns."""
        behavior_data = {
            'license_checks': False,
            'server_communication': False,
            'registry_access': False,
            'api_patterns': []
        }

        try:
            # Use subprocess to run dumpbin or similar PE analysis tool
            import subprocess

            # Try using dumpbin (Visual Studio tool) for import analysis
            try:
                result = subprocess.run(
                    ['dumpbin', '/imports', str(binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False
                )

                if result.returncode == 0:
                    imports_text = result.stdout.lower()

                    # Analyze imports for licensing patterns
                    license_apis = [
                        'regopenkeyex', 'regqueryvalueex', 'regsetvalueex',
                        'getcomputername', 'getuserprofile', 'getvolumeserial',
                        'cryptacquirecontext', 'cryptcreatehash'
                    ]

                    for api in license_apis:
                        if api in imports_text:
                            behavior_data['license_checks'] = True
                            behavior_data['api_patterns'].append(api)

                    # Check for network communication APIs
                    network_apis = [
                        'winhttpopen', 'internetopen', 'httpsendrequest',
                        'socket', 'connect', 'send', 'recv'
                    ]

                    for api in network_apis:
                        if api in imports_text:
                            behavior_data['server_communication'] = True
                            behavior_data['api_patterns'].append(api)

                    # Check for registry access
                    registry_apis = ['regopen', 'regquery', 'regset', 'regcreate']

                    for api in registry_apis:
                        if any(reg_api in imports_text for reg_api in registry_apis):
                            behavior_data['registry_access'] = True
                            break

                else:
                    self.logger.debug("dumpbin failed, trying alternative method")

            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.logger.debug("dumpbin not available, using alternative analysis")

            # Fallback: Use pefile library if available
            try:
                import pefile

                pe = pefile.PE(str(binary_path))

                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode().lower()

                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode().lower()

                                # Check for license-related APIs
                                if any(api in func_name for api in ['reg', 'crypt', 'license']):
                                    behavior_data['license_checks'] = True
                                    behavior_data['api_patterns'].append(func_name)

                                # Check for network APIs
                                if any(api in func_name for api in ['http', 'inet', 'socket']):
                                    behavior_data['server_communication'] = True
                                    behavior_data['api_patterns'].append(func_name)

                        # Check DLL names for patterns
                        if any(dll in dll_name for dll in ['wininet', 'winhttp', 'ws2_32']):
                            behavior_data['server_communication'] = True

                        if 'advapi32' in dll_name:
                            behavior_data['registry_access'] = True

                pe.close()

            except (ImportError, Exception) as e:
                self.logger.debug(f"pefile analysis failed: {e}")

        except Exception as e:
            self.logger.error(f"Import analysis failed: {e}")

        return behavior_data

    def _analyze_behavioral_strings(self, binary_path: Path) -> Dict[str, Any]:
        """Analyze strings for behavioral patterns."""
        behavior_data = {
            'file_access_patterns': False,
        }

        try:
            # Use subprocess to extract strings from binary
            import subprocess

            # Try using strings.exe (Sysinternals) or built-in strings command
            strings_commands = [
                ['strings.exe', str(binary_path)],  # Sysinternals strings
                ['strings', str(binary_path)],      # Unix/Linux strings
                ['findstr', '/r', '[a-zA-Z]', str(binary_path)]  # Windows fallback
            ]

            strings_output = ""

            for cmd in strings_commands:
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False
                    )

                    if result.returncode == 0 and result.stdout:
                        strings_output = result.stdout.lower()
                        break

                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue

            # If subprocess methods failed, try reading binary directly
            if not strings_output:
                try:
                    with open(binary_path, 'rb') as f:
                        binary_data = f.read()

                    # Extract printable ASCII strings (minimum length 4)
                    import re
                    strings_pattern = re.compile(b'[\x20-\x7E]{4,}')
                    matches = strings_pattern.findall(binary_data)
                    strings_list = [match.decode('ascii', errors='ignore').lower() for match in matches]
                    strings_output = '\n'.join(strings_list)

                except Exception as e:
                    self.logger.debug(f"Direct binary string extraction failed: {e}")

            if strings_output:
                # Analyze strings for file access patterns
                file_patterns = [
                    '.lic', '.license', 'license.dat', 'license.key',
                    '.cfg', '.config', '.ini', '.xml', '.json',
                    'appdata', 'programdata', 'program files',
                    'registry', 'hkey_', 'software\\',
                    'temp', 'temporary', '%temp%',
                    'getprivateprofilestring', 'writetofile'
                ]

                # Check for license file access patterns
                for pattern in file_patterns:
                    if pattern in strings_output:
                        behavior_data['file_access_patterns'] = True
                        break

                # Additional patterns for specific protection systems
                protection_strings = [
                    'flexlm', 'license manager', 'checkout license',
                    'adobe activation', 'creative cloud',
                    'hasp', 'sentinel', 'safenet',
                    'license server', 'floating license',
                    'trial period', 'evaluation copy',
                    'unauthorized copy', 'piracy detected'
                ]

                found_protection_strings = []
                for pattern in protection_strings:
                    if pattern in strings_output:
                        found_protection_strings.append(pattern)

                # If we found protection-related strings, likely has file access patterns
                if found_protection_strings:
                    behavior_data['file_access_patterns'] = True
                    behavior_data['protection_strings_found'] = found_protection_strings

        except Exception as e:
            self.logger.error(f"String analysis failed: {e}")

        return behavior_data

    def calculate_consensus(
        self,
        peid_results: List[Dict[str, Any]],
        die_results: List[Dict[str, Any]],
        protid_results: List[Dict[str, Any]],
        yara_results: List[Dict[str, Any]]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """Calculate consensus score from multiple scanner results with version tracking.

        Args:
            peid_results: PEiD scanner results
            die_results: DIE scanner results
            protid_results: Protection ID results
            yara_results: YARA validation results

        Returns:
            Tuple of (consensus_score, agreed_protection_details)
        """
        self.logger.info("Calculating cross-validation consensus with version tracking")

        # Aggregate all detections with version information
        all_detections = {}
        scanner_count = 0

        # Process each scanner's results
        scanner_results = [
            ('peid', peid_results),
            ('die', die_results),
            ('protid', protid_results),
            ('yara', yara_results)
        ]

        for scanner_name, results in scanner_results:
            if not results:
                continue

            scanner_count += 1

            for result in results:
                protection = result.get('protection', result.get('rule', 'unknown'))
                version = result.get('version', '')

                # Create compound key for protection + version
                if version:
                    protection_key = f"{protection.lower().strip()}::{version.lower().strip()}"
                    display_name = f"{protection} {version}".strip()
                else:
                    protection_key = protection.lower().strip()
                    display_name = protection

                if protection_key not in all_detections:
                    all_detections[protection_key] = {
                        'name': protection,
                        'version': version,
                        'display_name': display_name,
                        'scanners': [],
                        'scanner_details': [],
                        'confidence_sum': 0.0,
                        'count': 0
                    }

                all_detections[protection_key]['scanners'].append(scanner_name)
                all_detections[protection_key]['scanner_details'].append({
                    'scanner': scanner_name,
                    'confidence': result.get('confidence', 0.5),
                    'raw_output': result.get('raw_output', ''),
                    'timestamp': result.get('timestamp', time.time())
                })
                all_detections[protection_key]['confidence_sum'] += result.get('confidence', 0.5)
                all_detections[protection_key]['count'] += 1

        # Calculate consensus with version information preserved
        agreed_protections = []
        total_consensus = 0.0

        if scanner_count > 0:
            for _protection_key, data in all_detections.items():
                # Calculate agreement percentage
                unique_scanners = len(set(data['scanners']))
                agreement = unique_scanners / scanner_count
                avg_confidence = data['confidence_sum'] / data['count']

                # Require at least 60% scanner agreement
                if agreement >= 0.6:
                    protection_detail = {
                        'name': data['name'],
                        'version': data['version'],
                        'display_name': data['display_name'],
                        'agreement_score': agreement,
                        'confidence_score': avg_confidence,
                        'consensus_score': agreement * avg_confidence,
                        'scanner_count': unique_scanners,
                        'total_scanners': scanner_count,
                        'supporting_scanners': list(set(data['scanners'])),
                        'scanner_details': data['scanner_details']
                    }

                    agreed_protections.append(protection_detail)
                    total_consensus += agreement * avg_confidence

            # Overall consensus score
            if agreed_protections:
                consensus_score = total_consensus / len(agreed_protections)
            else:
                consensus_score = 0.0
        else:
            consensus_score = 0.0

        # Sort by consensus score (highest first)
        agreed_protections.sort(key=lambda x: x['consensus_score'], reverse=True)

        self.logger.info(
            f"Consensus: {consensus_score:.2f}, "
            f"Agreed protections with versions: {len(agreed_protections)}"
        )

        # Log detailed version information
        for protection in agreed_protections:
            version_info = f" v{protection['version']}" if protection['version'] else " (no version detected)"
            self.logger.info(
                f"  - {protection['name']}{version_info}: "
                f"consensus={protection['consensus_score']:.2f}, "
                f"scanners={'/'.join(protection['supporting_scanners'])}"
            )

        return consensus_score, agreed_protections

    def run_full_cross_validation(
        self,
        binary_path: Path,
        intellicrack_detection: str,
        vendor_specs: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Run complete cross-validation analysis with version tracking.

        Args:
            binary_path: Path to binary file
            intellicrack_detection: Intellicrack's detection result
            vendor_specs: Optional vendor specifications

        Returns:
            Complete validation results with version information
        """
        self.logger.info(f"Running full cross-validation for {binary_path}")

        result = ValidationResult(binary_path)
        result.validation_sources = self.available_scanners + ['yara', 'signatures']

        try:
            # Run all available scanners
            result.peid_results = self.run_peid_analysis(binary_path)
            result.die_results = self.run_die_analysis(binary_path)
            result.protid_results = self.run_protid_analysis(binary_path)
            result.yara_results = self.run_yara_validation(binary_path)

            # Calculate consensus with version tracking
            consensus_score, agreed_protection_details = self.calculate_consensus(
                result.peid_results,
                result.die_results,
                result.protid_results,
                result.yara_results
            )

            result.consensus_score = consensus_score
            result.agreed_protections = agreed_protection_details

            # Check if Intellicrack's detection agrees with consensus (including versions)
            intellicrack_lower = intellicrack_detection.lower()
            matches_consensus = False
            matched_protection = None

            for protection_detail in agreed_protection_details:
                # Check against protection name
                protection_name = protection_detail['name'].lower()
                display_name = protection_detail['display_name'].lower()

                # Multiple matching strategies
                name_match = (protection_name in intellicrack_lower or
                             intellicrack_lower in protection_name)
                display_match = (display_name in intellicrack_lower or
                               intellicrack_lower in display_name)

                # If version is present, also check version-specific matching
                version_match = False
                if protection_detail['version']:
                    version_lower = protection_detail['version'].lower()
                    version_match = version_lower in intellicrack_lower

                if name_match or display_match or version_match:
                    matches_consensus = True
                    matched_protection = protection_detail
                    break

            if matches_consensus:
                result.confidence_level = min(consensus_score + 0.2, 1.0)
                self.logger.info(
                    f"Intellicrack detection '{intellicrack_detection}' matches "
                    f"consensus protection '{matched_protection['display_name']}'"
                )
            else:
                result.confidence_level = max(consensus_score - 0.3, 0.0)

                # Record conflicting result with detailed version info
                consensus_names = [p['display_name'] for p in agreed_protection_details]
                result.conflicting_results.append({
                    'intellicrack_detection': intellicrack_detection,
                    'consensus_detections': consensus_names,
                    'consensus_details': agreed_protection_details,
                    'issue': 'intellicrack_disagreement'
                })

            # Vendor comparison if available
            if vendor_specs:
                vendor_comparison = self.compare_with_vendor_docs(
                    intellicrack_detection,
                    vendor_specs
                )
                if vendor_comparison['vendor_match']:
                    result.confidence_level = min(result.confidence_level + 0.1, 1.0)

            self.logger.info(
                f"Cross-validation complete. "
                f"Consensus: {consensus_score:.2f}, "
                f"Confidence: {result.confidence_level:.2f}, "
                f"Protections found: {len(agreed_protection_details)}"
            )

            return result

        except Exception as e:
            self.logger.error(f"Cross-validation failed: {e}")
            result.confidence_level = 0.0
            return result

    def save_validation_results(self, results: ValidationResult, output_path: Path) -> None:
        """Save validation results to file.

        Args:
            results: Validation results to save
            output_path: Output file path
        """
        try:
            results_data = {
                'binary_path': str(results.binary_path),
                'timestamp': results.timestamp,
                'peid_results': results.peid_results,
                'die_results': results.die_results,
                'protid_results': results.protid_results,
                'yara_results': results.yara_results,
                'consensus_score': results.consensus_score,
                'agreed_protections': results.agreed_protections,
                'conflicting_results': results.conflicting_results,
                'validation_sources': results.validation_sources,
                'confidence_level': results.confidence_level
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, default=str)

            self.logger.info(f"Validation results saved to {output_path}")

        except Exception as e:
            self.logger.error(f"Failed to save validation results: {e}")
            raise
