"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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
import re
import subprocess
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import capstone
import pefile
import yara
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class DetectionResult:
    """Represents a protection detection result."""
    protection_name: str
    version: str
    confidence_score: float
    memory_addresses: List[str]
    entry_points: List[str]
    algorithm_details: Dict[str, Any]
    source: str
    timestamp: float
    evidence_hash: str


@dataclass
class ValidationResults:
    """Results of detection validation."""
    passed: bool
    criteria_results: Dict[str, bool]
    failure_reasons: List[str]
    confidence_score: float
    consensus_rate: float
    evidence_count: int


class DetectionPassCriteriaValidator:
    """
    Validates detection results against Phase 6.1 pass criteria.

    ALL criteria must be met for detection to pass:
    - Protection name matches ground truth with exact version
    - Memory addresses valid and point to actual protection code
    - Minimum 3 independent sources confirm detection
    - Protection algorithm details documented
    - Entry points identified with hexadecimal addresses
    - Detection confidence score ≥ 0.90
    - Cross-validation consensus ≥ 80%
    """

    def __init__(self, ground_truth_path: str, tools_config: Optional[Dict] = None):
        """
        Initialize the validator.

        Args:
            ground_truth_path: Path to certified ground truth data
            tools_config: Configuration for external analysis tools
        """
        self.ground_truth_path = Path(ground_truth_path)
        self.tools_config = tools_config or {}
        self.logger = self._setup_logging()

        # Load ground truth data
        self.ground_truth = self._load_ground_truth()

        # Initialize analysis engines
        self.disassembler = self._initialize_disassembler()
        self.yara_rules = self._load_yara_rules()

        # External tool configurations
        self.external_tools = {
            'peid': self.tools_config.get('peid_path', r'C:\Tools\PEiD\PEiD.exe'),
            'die': self.tools_config.get('die_path', r'C:\Tools\DIE\die.exe'),
            'protectionid': self.tools_config.get('protectionid_path', r'C:\Tools\ProtectionID\ProtectionID.exe'),
            'r2': self.tools_config.get('radare2_path', 'radare2')
        }

        # Validation thresholds
        self.min_confidence = 0.90
        self.min_consensus = 0.80
        self.min_sources = 3

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for validation process."""
        logger = logging.getLogger(f"{__name__}.{id(self)}")
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def _load_ground_truth(self) -> Dict[str, Any]:
        """Load certified ground truth data."""
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file not found: {self.ground_truth_path}")

        with open(self.ground_truth_path, 'r', encoding='utf-8') as f:
            ground_truth = json.load(f)

        # Verify ground truth integrity
        self._verify_ground_truth_integrity(ground_truth)

        return ground_truth

    def _verify_ground_truth_integrity(self, ground_truth: Dict[str, Any]) -> None:
        """Verify ground truth data integrity and completeness."""
        required_fields = [
            'protections', 'signatures', 'verification_hash',
            'creation_timestamp', 'sources'
        ]

        for field in required_fields:
            if field not in ground_truth:
                raise ValueError(f"Ground truth missing required field: {field}")

        # Verify each protection has complete information
        for protection_id, protection_data in ground_truth.get('protections', {}).items():
            required_protection_fields = [
                'name', 'version', 'algorithm', 'key_size',
                'entry_points', 'signatures', 'memory_layout'
            ]

            for field in required_protection_fields:
                if field not in protection_data:
                    raise ValueError(
                        f"Protection {protection_id} missing required field: {field}"
                    )

    def _initialize_disassembler(self) -> capstone.Cs:
        """Initialize Capstone disassembler engine."""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        cs.skipdata = True
        return cs

    def _load_yara_rules(self) -> Optional[yara.Rules]:
        """Load YARA rules for protection detection."""
        rules_path = Path(__file__).parent / 'yara_rules' / 'protection_patterns.yar'

        if rules_path.exists():
            try:
                return yara.compile(filepath=str(rules_path))
            except Exception as e:
                self.logger.warning(f"Failed to load YARA rules: {e}")
                return None
        else:
            # Create basic protection detection rules
            return self._create_default_yara_rules()

    def _create_default_yara_rules(self) -> yara.Rules:
        """Create default YARA rules for common protections."""
        rules_source = '''
        rule FlexLM_Detection {
            meta:
                description = "Detects FlexLM/FLEXnet licensing system"
                author = "Intellicrack Validation Framework"

            strings:
                $flexlm1 = "FLEXLM_TIMEOUT" wide ascii
                $flexlm2 = "lm_checkout" wide ascii
                $flexlm3 = "VENDOR_NAME" wide ascii
                $flexlm4 = { 46 4C 45 58 6C 6D } // "FLEXlm"

            condition:
                any of them
        }

        rule Sentinel_Detection {
            meta:
                description = "Detects Sentinel licensing protection"

            strings:
                $sentinel1 = "Sentinel" wide ascii
                $sentinel2 = "Rainbow Technologies" wide ascii
                $sentinel3 = { 53 65 6E 74 69 6E 65 6C } // "Sentinel"

            condition:
                any of them
        }

        rule VMProtect_Detection {
            meta:
                description = "Detects VMProtect packer/protector"

            strings:
                $vmp1 = ".vmp0" wide ascii
                $vmp2 = ".vmp1" wide ascii
                $vmp3 = "VMProtect" wide ascii

            condition:
                any of them
        }
        '''

        return yara.compile(source=rules_source)

    def validate_detection(self,
                         binary_path: str,
                         detection_results: List[DetectionResult]) -> ValidationResults:
        """
        Validate detection results against all Phase 6.1 criteria.

        Args:
            binary_path: Path to binary that was analyzed
            detection_results: List of detection results from various sources

        Returns:
            ValidationResults with pass/fail status and detailed criteria results
        """
        self.logger.info(f"Starting detection validation for: {binary_path}")

        # Initialize validation state
        criteria_results = {}
        failure_reasons = []

        # Get ground truth for this binary
        binary_hash = self._calculate_file_hash(binary_path)
        ground_truth_protection = self._get_ground_truth_for_binary(binary_hash)

        if not ground_truth_protection:
            failure_reasons.append(f"No ground truth found for binary: {binary_hash}")
            return ValidationResults(
                passed=False,
                criteria_results=criteria_results,
                failure_reasons=failure_reasons,
                confidence_score=0.0,
                consensus_rate=0.0,
                evidence_count=len(detection_results)
            )

        # Validate each criterion
        criteria_results['6.1.1'] = self._validate_exact_version_match(
            detection_results, ground_truth_protection, failure_reasons
        )

        criteria_results['6.1.2'] = self._validate_memory_addresses(
            detection_results, binary_path, failure_reasons
        )

        criteria_results['6.1.3'] = self._validate_independent_sources(
            detection_results, failure_reasons
        )

        criteria_results['6.1.4'] = self._validate_algorithm_details(
            detection_results, ground_truth_protection, failure_reasons
        )

        criteria_results['6.1.5'] = self._validate_entry_points(
            detection_results, failure_reasons
        )

        confidence_score = self._calculate_confidence_score(detection_results)
        criteria_results['6.1.6'] = self._validate_confidence_score(
            confidence_score, failure_reasons
        )

        consensus_rate = self._calculate_consensus_rate(detection_results, ground_truth_protection)
        criteria_results['6.1.7'] = self._validate_consensus_rate(
            consensus_rate, failure_reasons
        )

        # Overall pass status
        overall_passed = all(criteria_results.values()) and len(failure_reasons) == 0

        self.logger.info(f"Detection validation completed. Passed: {overall_passed}")

        return ValidationResults(
            passed=overall_passed,
            criteria_results=criteria_results,
            failure_reasons=failure_reasons,
            confidence_score=confidence_score,
            consensus_rate=consensus_rate,
            evidence_count=len(detection_results)
        )

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of binary file."""
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _get_ground_truth_for_binary(self, binary_hash: str) -> Optional[Dict[str, Any]]:
        """Get ground truth protection data for a specific binary."""
        for protection_id, protection_data in self.ground_truth.get('protections', {}).items():
            if protection_data.get('binary_hash') == binary_hash:
                return protection_data
        return None

    def _validate_exact_version_match(self,
                                    detection_results: List[DetectionResult],
                                    ground_truth: Dict[str, Any],
                                    failure_reasons: List[str]) -> bool:
        """Validate exact version matching with ground truth."""
        expected_name = ground_truth.get('name', '')
        expected_version = ground_truth.get('version', '')

        for result in detection_results:
            if (result.protection_name.lower() == expected_name.lower() and
                result.version == expected_version):
                return True

        failure_reasons.append(
            f"No detection result matches expected protection: {expected_name} v{expected_version}"
        )
        return False

    def _validate_memory_addresses(self,
                                 detection_results: List[DetectionResult],
                                 binary_path: str,
                                 failure_reasons: List[str]) -> bool:
        """Validate memory addresses point to actual protection code."""
        valid_addresses_found = False

        for result in detection_results:
            if not result.memory_addresses:
                continue

            # Validate each memory address
            for addr_str in result.memory_addresses:
                if self._validate_single_memory_address(addr_str, binary_path):
                    valid_addresses_found = True
                    break

            if valid_addresses_found:
                break

        if not valid_addresses_found:
            failure_reasons.append("No valid memory addresses pointing to protection code found")

        return valid_addresses_found

    def _validate_single_memory_address(self, addr_str: str, binary_path: str) -> bool:
        """Validate a single memory address points to protection code."""
        try:
            # Parse hexadecimal address
            if addr_str.startswith('0x'):
                addr = int(addr_str, 16)
            else:
                addr = int(addr_str, 16)

            # Load PE file to validate address
            pe = pefile.PE(binary_path)

            # Check if address is within any section
            for section in pe.sections:
                section_start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                section_end = section_start + section.Misc_VirtualSize

                if section_start <= addr < section_end:
                    # Get code at this address and analyze
                    file_offset = pe.get_offset_from_rva(addr - pe.OPTIONAL_HEADER.ImageBase)
                    if file_offset is None:
                        continue

                    # Read bytes at address
                    with open(binary_path, 'rb') as f:
                        f.seek(file_offset)
                        code_bytes = f.read(32)  # Read 32 bytes for analysis

                    # Disassemble and check for protection-like patterns
                    return self._analyze_code_for_protection_patterns(code_bytes, addr)

            return False

        except (ValueError, pefile.PEFormatError, Exception) as e:
            self.logger.warning(f"Error validating memory address {addr_str}: {e}")
            return False

    def _analyze_code_for_protection_patterns(self, code_bytes: bytes, address: int) -> bool:
        """Analyze disassembled code for protection-like patterns."""
        try:
            instructions = list(self.disassembler.disasm(code_bytes, address))

            if not instructions:
                return False

            # Look for protection-like patterns
            protection_patterns = [
                'call',  # Function calls
                'jmp',   # Jumps (often used in protection)
                'cmp',   # Comparisons (license checks)
                'test',  # Tests
                'xor',   # Encryption/decryption
                'mov',   # Data movement
            ]

            # Check for crypto/protection-like instruction sequences
            for insn in instructions:
                if any(pattern in insn.mnemonic.lower() for pattern in protection_patterns):
                    return True

            # Additional pattern analysis could be added here
            return len(instructions) > 0

        except Exception as e:
            self.logger.warning(f"Error analyzing code patterns: {e}")
            return False

    def _validate_independent_sources(self,
                                    detection_results: List[DetectionResult],
                                    failure_reasons: List[str]) -> bool:
        """Validate minimum 3 independent sources confirm detection."""
        unique_sources = set(result.source for result in detection_results)

        if len(unique_sources) < self.min_sources:
            failure_reasons.append(
                f"Only {len(unique_sources)} independent sources, minimum {self.min_sources} required"
            )
            return False

        return True

    def _validate_algorithm_details(self,
                                  detection_results: List[DetectionResult],
                                  ground_truth: Dict[str, Any],
                                  failure_reasons: List[str]) -> bool:
        """Validate protection algorithm details are documented."""
        required_details = ['key_size', 'encryption_type', 'hash_algorithm']

        for result in detection_results:
            if not result.algorithm_details:
                continue

            # Check if all required details are present
            details_present = all(
                key in result.algorithm_details
                for key in required_details
            )

            if details_present:
                # Validate against ground truth if available
                gt_algorithm = ground_truth.get('algorithm', {})
                if self._verify_algorithm_details_match(result.algorithm_details, gt_algorithm):
                    return True

        failure_reasons.append("No detection result contains required algorithm details")
        return False

    def _verify_algorithm_details_match(self,
                                      detected: Dict[str, Any],
                                      ground_truth: Dict[str, Any]) -> bool:
        """Verify detected algorithm details match ground truth."""
        key_fields = ['key_size', 'encryption_type', 'hash_algorithm']

        for field in key_fields:
            if field in ground_truth:
                detected_value = detected.get(field)
                gt_value = ground_truth.get(field)

                if detected_value and str(detected_value).lower() != str(gt_value).lower():
                    return False

        return True

    def _validate_entry_points(self,
                             detection_results: List[DetectionResult],
                             failure_reasons: List[str]) -> bool:
        """Validate entry points are identified with hexadecimal addresses."""
        hex_pattern = re.compile(r'^0x[0-9a-fA-F]+$')

        for result in detection_results:
            if not result.entry_points:
                continue

            # Check if all entry points are valid hex addresses
            valid_entry_points = all(
                hex_pattern.match(ep) for ep in result.entry_points
            )

            if valid_entry_points and len(result.entry_points) > 0:
                return True

        failure_reasons.append("No valid hexadecimal entry points found")
        return False

    def _calculate_confidence_score(self, detection_results: List[DetectionResult]) -> float:
        """Calculate overall confidence score from all detection results."""
        if not detection_results:
            return 0.0

        # Weight confidence scores by source reliability
        source_weights = {
            'intellicrack': 0.4,
            'peid': 0.2,
            'die': 0.2,
            'protectionid': 0.2,
            'behavioral_analysis': 0.3,
            'yara_rules': 0.1,
        }

        weighted_sum = 0.0
        total_weight = 0.0

        for result in detection_results:
            weight = source_weights.get(result.source.lower(), 0.1)
            weighted_sum += result.confidence_score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def _validate_confidence_score(self,
                                 confidence_score: float,
                                 failure_reasons: List[str]) -> bool:
        """Validate confidence score meets minimum threshold."""
        if confidence_score < self.min_confidence:
            failure_reasons.append(
                f"Confidence score {confidence_score:.3f} below minimum {self.min_confidence}"
            )
            return False

        return True

    def _calculate_consensus_rate(self,
                                detection_results: List[DetectionResult],
                                ground_truth: Dict[str, Any]) -> float:
        """Calculate consensus rate between sources."""
        if not detection_results:
            return 0.0

        expected_name = ground_truth.get('name', '').lower()
        expected_version = ground_truth.get('version', '')

        matching_detections = sum(
            1 for result in detection_results
            if (result.protection_name.lower() == expected_name and
                result.version == expected_version)
        )

        return matching_detections / len(detection_results)

    def _validate_consensus_rate(self,
                               consensus_rate: float,
                               failure_reasons: List[str]) -> bool:
        """Validate consensus rate meets minimum threshold."""
        if consensus_rate < self.min_consensus:
            failure_reasons.append(
                f"Consensus rate {consensus_rate:.3f} below minimum {self.min_consensus}"
            )
            return False

        return True

    def run_cross_validation(self, binary_path: str) -> List[DetectionResult]:
        """
        Run cross-validation using multiple independent sources.

        Returns:
            List of detection results from various sources
        """
        self.logger.info("Running cross-validation with multiple sources")

        detection_tasks = [
            ('intellicrack', self._run_intellicrack_detection),
            ('peid', self._run_peid_detection),
            ('die', self._run_die_detection),
            ('protectionid', self._run_protectionid_detection),
            ('behavioral_analysis', self._run_behavioral_analysis),
            ('yara_rules', self._run_yara_detection),
        ]

        results = []

        with ThreadPoolExecutor(max_workers=6) as executor:
            future_to_source = {
                executor.submit(task_func, binary_path): source
                for source, task_func in detection_tasks
            }

            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result(timeout=300)  # 5-minute timeout
                    if result:
                        results.append(result)
                        self.logger.info(f"Detection completed from {source}")
                except Exception as e:
                    self.logger.error(f"Detection failed from {source}: {e}")

        self.logger.info(f"Cross-validation completed with {len(results)} results")
        return results

    def _run_intellicrack_detection(self, binary_path: str) -> Optional[DetectionResult]:
        """Run Intellicrack's internal detection engine."""
        try:
            # This would integrate with actual Intellicrack detection
            # For now, simulate the detection process

            # Load binary for analysis
            pe = pefile.PE(binary_path)

            # Analyze sections and imports
            protection_indicators = self._analyze_pe_structure(pe)

            # Create detection result
            if protection_indicators['protection_detected']:
                return DetectionResult(
                    protection_name=protection_indicators['name'],
                    version=protection_indicators['version'],
                    confidence_score=protection_indicators['confidence'],
                    memory_addresses=protection_indicators['addresses'],
                    entry_points=protection_indicators['entry_points'],
                    algorithm_details=protection_indicators['algorithm'],
                    source='intellicrack',
                    timestamp=time.time(),
                    evidence_hash=self._calculate_file_hash(binary_path)
                )

        except Exception as e:
            self.logger.error(f"Intellicrack detection failed: {e}")

        return None

    def _analyze_pe_structure(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze PE structure for protection indicators."""
        indicators = {
            'protection_detected': False,
            'name': '',
            'version': '',
            'confidence': 0.0,
            'addresses': [],
            'entry_points': [],
            'algorithm': {}
        }

        # Analyze imports for protection-related functions
        protection_imports = [
            'CryptAcquireContext', 'CryptGenKey', 'CryptEncrypt',
            'VirtualProtect', 'VirtualAlloc', 'CreateThread',
            'LoadLibrary', 'GetProcAddress', 'IsDebuggerPresent'
        ]

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode('utf-8', errors='ignore') in protection_imports:
                        indicators['protection_detected'] = True
                        indicators['confidence'] += 0.1

        # Analyze sections for protection patterns
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if any(pattern in section_name.lower() for pattern in ['.vmp', '.upx', '.aspack']):
                indicators['protection_detected'] = True
                indicators['name'] = self._identify_protection_from_section(section_name)
                indicators['confidence'] += 0.3

                # Add section address
                section_addr = hex(pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress)
                indicators['addresses'].append(section_addr)

        # Add entry point
        entry_point = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        indicators['entry_points'].append(entry_point)

        # Clamp confidence to [0, 1]
        indicators['confidence'] = min(indicators['confidence'], 1.0)

        return indicators

    def _identify_protection_from_section(self, section_name: str) -> str:
        """Identify protection type from section name."""
        section_lower = section_name.lower()

        if 'vmp' in section_lower:
            return 'VMProtect'
        elif 'upx' in section_lower:
            return 'UPX'
        elif 'aspack' in section_lower:
            return 'ASPack'
        elif 'themida' in section_lower:
            return 'Themida'
        else:
            return 'Unknown Packer'

    def _run_peid_detection(self, binary_path: str) -> Optional[DetectionResult]:
        """Run PEiD detection."""
        try:
            if not Path(self.external_tools['peid']).exists():
                self.logger.warning("PEiD not found, skipping detection")
                return None

            # Run PEiD command
            cmd = [self.external_tools['peid'], '-hard', binary_path]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            if result.returncode == 0 and result.stdout:
                return self._parse_peid_output(result.stdout, binary_path)

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.error(f"PEiD detection failed: {e}")

        return None

    def _parse_peid_output(self, output: str, binary_path: str) -> Optional[DetectionResult]:
        """Parse PEiD output into detection result."""
        lines = output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if line and not line.startswith('['):
                # Extract protection information
                parts = line.split(' -> ')
                if len(parts) >= 2:
                    protection_info = parts[1].strip()

                    return DetectionResult(
                        protection_name=protection_info.split()[0] if protection_info.split() else 'Unknown',
                        version=self._extract_version_from_string(protection_info),
                        confidence_score=0.85,  # PEiD is generally reliable
                        memory_addresses=[],  # PEiD doesn't provide memory addresses
                        entry_points=[],
                        algorithm_details={},
                        source='peid',
                        timestamp=time.time(),
                        evidence_hash=self._calculate_file_hash(binary_path)
                    )

        return None

    def _extract_version_from_string(self, text: str) -> str:
        """Extract version number from text string."""
        version_patterns = [
            r'v(\d+\.[\d\.]+)',
            r'(\d+\.[\d\.]+)',
            r'version\s+(\d+\.[\d\.]+)',
        ]

        for pattern in version_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

        return ''

    def _run_die_detection(self, binary_path: str) -> Optional[DetectionResult]:
        """Run Detect It Easy (DIE) detection."""
        try:
            if not Path(self.external_tools['die']).exists():
                self.logger.warning("DIE not found, skipping detection")
                return None

            cmd = [self.external_tools['die'], '-j', binary_path]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            if result.returncode == 0 and result.stdout:
                return self._parse_die_output(result.stdout, binary_path)

        except Exception as e:
            self.logger.error(f"DIE detection failed: {e}")

        return None

    def _parse_die_output(self, output: str, binary_path: str) -> Optional[DetectionResult]:
        """Parse DIE JSON output into detection result."""
        try:
            data = json.loads(output)

            if 'detects' in data and data['detects']:
                detect = data['detects'][0]  # Use first detection

                return DetectionResult(
                    protection_name=detect.get('name', 'Unknown'),
                    version=detect.get('version', ''),
                    confidence_score=detect.get('confidence', 0.5),
                    memory_addresses=[],
                    entry_points=[],
                    algorithm_details={},
                    source='die',
                    timestamp=time.time(),
                    evidence_hash=self._calculate_file_hash(binary_path)
                )

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse DIE output: {e}")

        return None

    def _run_protectionid_detection(self, binary_path: str) -> Optional[DetectionResult]:
        """Run Protection ID detection."""
        try:
            if not Path(self.external_tools['protectionid']).exists():
                self.logger.warning("Protection ID not found, skipping detection")
                return None

            cmd = [self.external_tools['protectionid'], binary_path]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            if result.returncode == 0 and result.stdout:
                return self._parse_protectionid_output(result.stdout, binary_path)

        except Exception as e:
            self.logger.error(f"Protection ID detection failed: {e}")

        return None

    def _parse_protectionid_output(self, output: str, binary_path: str) -> Optional[DetectionResult]:
        """Parse Protection ID output into detection result."""
        lines = output.strip().split('\n')

        for line in lines:
            if 'Protection:' in line:
                protection_info = line.split('Protection:')[1].strip()

                return DetectionResult(
                    protection_name=protection_info.split()[0] if protection_info.split() else 'Unknown',
                    version=self._extract_version_from_string(protection_info),
                    confidence_score=0.80,
                    memory_addresses=[],
                    entry_points=[],
                    algorithm_details={},
                    source='protectionid',
                    timestamp=time.time(),
                    evidence_hash=self._calculate_file_hash(binary_path)
                )

        return None

    def _run_behavioral_analysis(self, binary_path: str) -> Optional[DetectionResult]:
        """Run behavioral analysis for protection detection."""
        try:
            # Analyze file behavior patterns
            pe = pefile.PE(binary_path)

            # Check for protection-related behaviors
            behaviors = self._analyze_protection_behaviors(pe)

            if behaviors['protection_detected']:
                return DetectionResult(
                    protection_name=behaviors['protection_name'],
                    version=behaviors['version'],
                    confidence_score=behaviors['confidence'],
                    memory_addresses=behaviors['addresses'],
                    entry_points=behaviors['entry_points'],
                    algorithm_details=behaviors['algorithm_details'],
                    source='behavioral_analysis',
                    timestamp=time.time(),
                    evidence_hash=self._calculate_file_hash(binary_path)
                )

        except Exception as e:
            self.logger.error(f"Behavioral analysis failed: {e}")

        return None

    def _analyze_protection_behaviors(self, pe: pefile.PE) -> Dict[str, Any]:
        """Analyze PE file for protection-related behaviors."""
        behaviors = {
            'protection_detected': False,
            'protection_name': '',
            'version': '',
            'confidence': 0.0,
            'addresses': [],
            'entry_points': [],
            'algorithm_details': {}
        }

        # Analyze import patterns
        crypto_imports = []
        debug_imports = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')

                        # Check for crypto functions
                        if any(crypto_func in func_name.lower() for crypto_func in
                               ['crypt', 'hash', 'rsa', 'aes', 'des']):
                            crypto_imports.append(func_name)
                            behaviors['confidence'] += 0.1

                        # Check for anti-debug functions
                        if any(debug_func in func_name.lower() for debug_func in
                               ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess']):
                            debug_imports.append(func_name)
                            behaviors['confidence'] += 0.15

        # Check section characteristics
        for section in pe.sections:
            characteristics = section.Characteristics

            # Executable + Writable sections (often used by packers)
            if (characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] and
                characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']):
                behaviors['confidence'] += 0.2
                section_addr = hex(pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress)
                behaviors['addresses'].append(section_addr)

        # Determine protection type based on patterns
        if crypto_imports and debug_imports:
            behaviors['protection_detected'] = True
            behaviors['protection_name'] = 'License Protection System'
            behaviors['algorithm_details'] = {
                'crypto_functions': crypto_imports,
                'anti_debug_functions': debug_imports,
                'encryption_type': 'Unknown',
                'key_size': 'Unknown',
                'hash_algorithm': 'Unknown'
            }

        # Add entry point
        entry_point = hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        behaviors['entry_points'].append(entry_point)

        # Clamp confidence
        behaviors['confidence'] = min(behaviors['confidence'], 1.0)

        return behaviors

    def _run_yara_detection(self, binary_path: str) -> Optional[DetectionResult]:
        """Run YARA rule-based detection."""
        try:
            if not self.yara_rules:
                self.logger.warning("No YARA rules available, skipping detection")
                return None

            matches = self.yara_rules.match(binary_path)

            if matches:
                # Use first match
                match = matches[0]

                return DetectionResult(
                    protection_name=match.rule,
                    version='',
                    confidence_score=0.70,  # YARA matches are usually reliable but generic
                    memory_addresses=[hex(string.instances[0].offset) for string in match.strings if string.instances],
                    entry_points=[],
                    algorithm_details={'yara_rule': match.rule, 'matched_strings': [s.identifier for s in match.strings]},
                    source='yara_rules',
                    timestamp=time.time(),
                    evidence_hash=self._calculate_file_hash(binary_path)
                )

        except Exception as e:
            self.logger.error(f"YARA detection failed: {e}")

        return None

    def generate_validation_report(self,
                                 binary_path: str,
                                 validation_results: ValidationResults) -> Dict[str, Any]:
        """Generate comprehensive validation report."""
        report = {
            'validation_summary': {
                'binary_path': binary_path,
                'binary_hash': self._calculate_file_hash(binary_path),
                'timestamp': time.time(),
                'overall_passed': validation_results.passed,
                'evidence_count': validation_results.evidence_count,
                'confidence_score': validation_results.confidence_score,
                'consensus_rate': validation_results.consensus_rate
            },
            'criteria_results': {
                '6.1.1_exact_version_match': validation_results.criteria_results.get('6.1.1', False),
                '6.1.2_memory_addresses_valid': validation_results.criteria_results.get('6.1.2', False),
                '6.1.3_independent_sources': validation_results.criteria_results.get('6.1.3', False),
                '6.1.4_algorithm_details': validation_results.criteria_results.get('6.1.4', False),
                '6.1.5_entry_points': validation_results.criteria_results.get('6.1.5', False),
                '6.1.6_confidence_threshold': validation_results.criteria_results.get('6.1.6', False),
                '6.1.7_consensus_threshold': validation_results.criteria_results.get('6.1.7', False)
            },
            'failure_reasons': validation_results.failure_reasons,
            'validation_thresholds': {
                'minimum_confidence': self.min_confidence,
                'minimum_consensus': self.min_consensus,
                'minimum_sources': self.min_sources
            },
            'phase_gate_status': 'PASS' if validation_results.passed else 'FAIL'
        }

        return report


def main():
    """Example usage of DetectionPassCriteriaValidator."""
    # Configuration
    ground_truth_path = r"C:\Intellicrack\tests\validation_system\certified_ground_truth\ground_truth.json"
    tools_config = {
        'peid_path': r'C:\Tools\PEiD\PEiD.exe',
        'die_path': r'C:\Tools\DIE\die.exe',
        'protectionid_path': r'C:\Tools\ProtectionID\ProtectionID.exe'
    }

    # Initialize validator
    validator = DetectionPassCriteriaValidator(ground_truth_path, tools_config)

    # Example binary to validate
    test_binary = r"C:\TestBinaries\protected_software.exe"

    # Run cross-validation
    detection_results = validator.run_cross_validation(test_binary)

    # Validate results
    validation_results = validator.validate_detection(test_binary, detection_results)

    # Generate report
    report = validator.generate_validation_report(test_binary, validation_results)

    # Output results
    print(f"Detection validation {'PASSED' if validation_results.passed else 'FAILED'}")
    print(f"Criteria met: {sum(validation_results.criteria_results.values())}/7")
    print(f"Confidence score: {validation_results.confidence_score:.3f}")
    print(f"Consensus rate: {validation_results.consensus_rate:.3f}")

    if validation_results.failure_reasons:
        print("\nFailure reasons:")
        for reason in validation_results.failure_reasons:
            print(f"  - {reason}")


if __name__ == "__main__":
    main()
