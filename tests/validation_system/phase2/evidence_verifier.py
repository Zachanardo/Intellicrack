"""
Phase 2: Evidence Verification and Integrity Validation
Specialized validation for evidence authenticity and integrity
"""

import asyncio
import hashlib
import json
import logging
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Capstone for disassembly verification
try:
    import capstone
except ImportError:
    capstone = None

# R2pipe for radare2 integration verification
try:
    import r2pipe
except ImportError:
    r2pipe = None

# Intellicrack utilities
try:
    from intellicrack.utils.binary_utils import BinaryUtils
    from intellicrack.utils.crypto_utils import CryptoUtils
    from intellicrack.utils.logging_utils import get_logger
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from intellicrack.utils.binary_utils import BinaryUtils
    from intellicrack.utils.crypto_utils import CryptoUtils
    from intellicrack.utils.logging_utils import get_logger


@dataclass
class EvidenceIntegrityReport:
    """Comprehensive evidence integrity assessment."""
    evidence_id: str
    timestamp: str
    binary_path: str
    integrity_score: float
    authenticity_verified: bool
    temporal_consistency: bool
    cryptographic_verification: dict[str, Any]
    memory_address_validation: dict[str, Any]
    disassembly_verification: dict[str, Any]
    import_table_validation: dict[str, Any]
    string_analysis_validation: dict[str, Any]
    entropy_verification: dict[str, Any]
    cross_reference_validation: dict[str, Any]
    anomaly_detection: list[str]
    confidence_assessment: str
    verification_metadata: dict[str, Any]


@dataclass
class EvidenceVerificationConfig:
    """Configuration for evidence verification processes."""
    max_evidence_age_hours: int = 24
    minimum_integrity_threshold: float = 0.90
    cryptographic_verification: bool = True
    deep_binary_analysis: bool = True
    cross_reference_validation: bool = True
    anomaly_detection_enabled: bool = True
    verification_timeout_seconds: int = 120
    evidence_storage_path: Path = Path("evidence_storage")


class EvidenceVerifier:
    """
    Specialized verifier for protection detection evidence integrity and authenticity.
    Ensures that collected evidence is genuine, unmodified, and cryptographically sound.
    """

    def __init__(self, config: EvidenceVerificationConfig | None = None, logger: logging.Logger | None = None):
        """Initialize evidence verifier with comprehensive validation capabilities."""
        self.config = config or EvidenceVerificationConfig()
        self.logger = logger or get_logger(__name__)

        # Initialize crypto and binary utilities
        try:
            self.crypto_utils = CryptoUtils()
            self.binary_utils = BinaryUtils()
        except Exception as e:
            self.logger.warning(f"Some utilities unavailable: {e}")
            self.crypto_utils = None
            self.binary_utils = None

        # Verification statistics
        self.verification_stats = {
            'total_verifications': 0,
            'successful_verifications': 0,
            'failed_verifications': 0,
            'integrity_violations': 0,
            'anomalies_detected': 0
        }

        self.logger.info("EvidenceVerifier initialized successfully")

    async def verify_evidence_integrity(self, evidence_data: dict[str, Any],
                                      binary_path: Path) -> EvidenceIntegrityReport:
        """
        Perform comprehensive verification of evidence integrity and authenticity.

        Args:
            evidence_data: Evidence data collected by DetectionEvidenceCollector
            binary_path: Path to the binary file that was analyzed

        Returns:
            EvidenceIntegrityReport with detailed integrity assessment
        """
        start_time = time.time()
        evidence_id = self._generate_evidence_id(evidence_data, binary_path)

        try:
            self.logger.info(f"Starting evidence verification for binary: {binary_path}")

            # Phase 1: Cryptographic verification
            crypto_verification = await self._verify_cryptographic_integrity(evidence_data, binary_path)

            # Phase 2: Temporal consistency validation
            temporal_consistency = self._verify_temporal_consistency(evidence_data)

            # Phase 3: Memory address validation
            memory_validation = await self._validate_memory_addresses(evidence_data, binary_path)

            # Phase 4: Disassembly verification
            disassembly_verification = await self._verify_disassembly_evidence(evidence_data, binary_path)

            # Phase 5: Import table validation
            import_validation = await self._validate_import_analysis(evidence_data, binary_path)

            # Phase 6: String analysis validation
            string_validation = await self._validate_string_analysis(evidence_data, binary_path)

            # Phase 7: Entropy verification
            entropy_verification = await self._verify_entropy_analysis(evidence_data, binary_path)

            # Phase 8: Cross-reference validation
            cross_ref_validation = await self._validate_cross_references(evidence_data)

            # Phase 9: Anomaly detection
            anomalies = await self._detect_anomalies(evidence_data, binary_path)

            # Phase 10: Calculate overall integrity score
            integrity_score = self._calculate_integrity_score(
                crypto_verification, temporal_consistency, memory_validation,
                disassembly_verification, import_validation, string_validation,
                entropy_verification, cross_ref_validation, anomalies
            )

            # Phase 11: Determine authenticity
            authenticity_verified = self._determine_authenticity(integrity_score, anomalies)

            # Phase 12: Generate confidence assessment
            confidence_assessment = self._assess_confidence(integrity_score, authenticity_verified)

            # Create verification metadata
            verification_metadata = {
                'verification_time': time.time() - start_time,
                'verifier_version': '2.0.0',
                'verification_timestamp': datetime.now(timezone.utc).isoformat(),
                'binary_hash': self._calculate_binary_hash(binary_path),
                'evidence_hash': self._calculate_evidence_hash(evidence_data)
            }

            # Update statistics
            self._update_verification_stats(authenticity_verified, len(anomalies))

            # Create comprehensive report
            report = EvidenceIntegrityReport(
                evidence_id=evidence_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                binary_path=str(binary_path),
                integrity_score=integrity_score,
                authenticity_verified=authenticity_verified,
                temporal_consistency=temporal_consistency,
                cryptographic_verification=crypto_verification,
                memory_address_validation=memory_validation,
                disassembly_verification=disassembly_verification,
                import_table_validation=import_validation,
                string_analysis_validation=string_validation,
                entropy_verification=entropy_verification,
                cross_reference_validation=cross_ref_validation,
                anomaly_detection=anomalies,
                confidence_assessment=confidence_assessment,
                verification_metadata=verification_metadata
            )

            self.logger.info(f"Evidence verification completed - Integrity: {integrity_score:.3f}, Authentic: {authenticity_verified}")
            return report

        except Exception as e:
            self.logger.error(f"Evidence verification failed: {str(e)}")
            return EvidenceIntegrityReport(
                evidence_id=evidence_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                binary_path=str(binary_path),
                integrity_score=0.0,
                authenticity_verified=False,
                temporal_consistency=False,
                cryptographic_verification={'error': str(e)},
                memory_address_validation={'error': str(e)},
                disassembly_verification={'error': str(e)},
                import_table_validation={'error': str(e)},
                string_analysis_validation={'error': str(e)},
                entropy_verification={'error': str(e)},
                cross_reference_validation={'error': str(e)},
                anomaly_detection=[f"Verification failed: {str(e)}"],
                confidence_assessment="FAILED",
                verification_metadata={'error': str(e), 'verification_time': time.time() - start_time}
            )

    async def _verify_cryptographic_integrity(self, evidence_data: dict[str, Any],
                                            binary_path: Path) -> dict[str, Any]:
        """Verify cryptographic integrity of evidence data."""
        if not self.config.cryptographic_verification:
            return {'verification_skipped': True}

        try:
            verification_result = {
                'binary_hash_verified': False,
                'evidence_hash_consistency': False,
                'digital_signature_valid': False,
                'cryptographic_score': 0.0
            }

            # Verify binary file hash consistency
            if binary_path.exists():
                current_binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()
                stored_hash = evidence_data.get('verification_metadata', {}).get('binary_hash', '')
                verification_result['binary_hash_verified'] = current_binary_hash == stored_hash

            # Verify evidence hash consistency
            calculated_evidence_hash = self._calculate_evidence_hash(evidence_data)
            stored_evidence_hash = evidence_data.get('evidence_summary', {}).get('evidence_hash', '')
            verification_result['evidence_hash_consistency'] = calculated_evidence_hash == stored_evidence_hash

            # Cryptographic signature verification (if available)
            if self.crypto_utils:
                signature_data = evidence_data.get('cryptographic_signature', {})
                if signature_data:
                    verification_result['digital_signature_valid'] = self.crypto_utils.verify_signature(
                        evidence_data, signature_data
                    )
                else:
                    # No signature present - generate one for future verification
                    signature = self.crypto_utils.generate_signature(evidence_data)
                    verification_result['signature_generated'] = signature is not None

            # Calculate cryptographic score
            score_components = [
                1.0 if verification_result['binary_hash_verified'] else 0.0,
                1.0 if verification_result['evidence_hash_consistency'] else 0.0,
                1.0 if verification_result.get('digital_signature_valid', False) else 0.5
            ]
            verification_result['cryptographic_score'] = sum(score_components) / len(score_components)

            return verification_result

        except Exception as e:
            self.logger.error(f"Cryptographic verification failed: {str(e)}")
            return {'error': str(e), 'cryptographic_score': 0.0}

    def _verify_temporal_consistency(self, evidence_data: dict[str, Any]) -> bool:
        """Verify temporal consistency of evidence timestamps."""
        try:
            current_time = datetime.now(timezone.utc)
            max_age = timedelta(hours=self.config.max_evidence_age_hours)

            # Check main evidence timestamp
            evidence_timestamp_str = evidence_data.get('evidence_summary', {}).get('collection_timestamp', '')
            if evidence_timestamp_str:
                evidence_timestamp = datetime.fromisoformat(evidence_timestamp_str.replace('Z', '+00:00'))
                if current_time - evidence_timestamp > max_age:
                    self.logger.warning(f"Evidence older than {self.config.max_evidence_age_hours} hours")
                    return False

            # Check individual protection evidence timestamps
            protection_evidence = evidence_data.get('protection_evidence', {})
            for protection_name, protection_data in protection_evidence.items():
                protection_timestamp_str = protection_data.get('evidence_timestamp', '')
                if protection_timestamp_str:
                    protection_timestamp = datetime.fromisoformat(protection_timestamp_str.replace('Z', '+00:00'))
                    if current_time - protection_timestamp > max_age:
                        self.logger.warning(f"Protection evidence for {protection_name} older than threshold")
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Temporal consistency verification failed: {str(e)}")
            return False

    async def _validate_memory_addresses(self, evidence_data: dict[str, Any],
                                       binary_path: Path) -> dict[str, Any]:
        """Validate authenticity of memory addresses in evidence."""
        try:
            validation_result = {
                'addresses_verified': 0,
                'addresses_invalid': 0,
                'address_ranges_valid': True,
                'pe_section_consistency': True,
                'validation_score': 0.0
            }

            if not r2pipe:
                return {'error': 'r2pipe not available for memory address validation'}

            # Open binary for analysis
            with r2pipe.open(str(binary_path)) as r2:
                r2.cmd('aaa')  # Analyze all

                # Get PE sections for validation
                sections = r2.cmdj('iSj') or []
                section_ranges = [(s.get('vaddr', 0), s.get('vaddr', 0) + s.get('vsize', 0))
                                for s in sections if s.get('vaddr')]

                protection_evidence = evidence_data.get('protection_evidence', {})

                for _protection_name, protection_data in protection_evidence.items():
                    memory_addresses = protection_data.get('memory_addresses', [])

                    for addr_info in memory_addresses:
                        addr = addr_info.get('address', 0)
                        if isinstance(addr, str):
                            try:
                                addr = int(addr, 16)
                            except ValueError:
                                validation_result['addresses_invalid'] += 1
                                continue

                        # Validate address is within valid PE sections
                        addr_valid = any(start <= addr < end for start, end in section_ranges)
                        if addr_valid:
                            validation_result['addresses_verified'] += 1
                        else:
                            validation_result['addresses_invalid'] += 1
                            validation_result['pe_section_consistency'] = False

                # Calculate validation score
                total_addresses = validation_result['addresses_verified'] + validation_result['addresses_invalid']
                if total_addresses > 0:
                    validation_result['validation_score'] = validation_result['addresses_verified'] / total_addresses
                else:
                    validation_result['validation_score'] = 1.0

            return validation_result

        except Exception as e:
            self.logger.error(f"Memory address validation failed: {str(e)}")
            return {'error': str(e), 'validation_score': 0.0}

    async def _verify_disassembly_evidence(self, evidence_data: dict[str, Any],
                                         binary_path: Path) -> dict[str, Any]:
        """Verify authenticity of disassembly evidence."""
        try:
            verification_result = {
                'instructions_verified': 0,
                'instructions_invalid': 0,
                'assembly_syntax_valid': True,
                'instruction_consistency': True,
                'verification_score': 0.0
            }

            if not capstone:
                return {'error': 'Capstone not available for disassembly verification'}

            # Initialize Capstone disassembler
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            cs.detail = True

            protection_evidence = evidence_data.get('protection_evidence', {})

            for _protection_name, protection_data in protection_evidence.items():
                disassembly_proof = protection_data.get('disassembly_proof', [])

                for proof_item in disassembly_proof:
                    address = proof_item.get('address', 0)
                    bytes_data = proof_item.get('bytes', '')
                    instructions = proof_item.get('instructions', [])

                    # Convert hex string to bytes
                    if isinstance(bytes_data, str):
                        try:
                            binary_data = bytes.fromhex(bytes_data.replace(' ', ''))
                        except ValueError:
                            verification_result['instructions_invalid'] += 1
                            verification_result['assembly_syntax_valid'] = False
                            continue
                    else:
                        binary_data = bytes_data

                    # Disassemble and verify
                    try:
                        disassembled = list(cs.disasm(binary_data, address))

                        # Verify instruction count matches
                        if len(disassembled) == len(instructions):
                            verification_result['instructions_verified'] += len(instructions)
                        else:
                            verification_result['instructions_invalid'] += len(instructions)
                            verification_result['instruction_consistency'] = False

                    except capstone.CsError:
                        verification_result['instructions_invalid'] += len(instructions)
                        verification_result['assembly_syntax_valid'] = False

            # Calculate verification score
            total_instructions = verification_result['instructions_verified'] + verification_result['instructions_invalid']
            if total_instructions > 0:
                verification_result['verification_score'] = verification_result['instructions_verified'] / total_instructions
            else:
                verification_result['verification_score'] = 1.0

            return verification_result

        except Exception as e:
            self.logger.error(f"Disassembly verification failed: {str(e)}")
            return {'error': str(e), 'verification_score': 0.0}

    async def _validate_import_analysis(self, evidence_data: dict[str, Any],
                                      binary_path: Path) -> dict[str, Any]:
        """Validate import analysis evidence against actual binary imports."""
        try:
            validation_result = {
                'imports_verified': 0,
                'imports_missing': 0,
                'dll_consistency': True,
                'function_name_accuracy': True,
                'validation_score': 0.0
            }

            if not r2pipe:
                return {'error': 'r2pipe not available for import validation'}

            # Get actual imports from binary
            with r2pipe.open(str(binary_path)) as r2:
                actual_imports = r2.cmdj('iij') or []
                actual_import_set = set()

                for imp in actual_imports:
                    dll_name = imp.get('libname', '').lower()
                    func_name = imp.get('name', '')
                    if dll_name and func_name:
                        actual_import_set.add(f"{dll_name}:{func_name}")

                protection_evidence = evidence_data.get('protection_evidence', {})

                for _protection_name, protection_data in protection_evidence.items():
                    import_analysis = protection_data.get('import_analysis', {})
                    suspicious_imports = import_analysis.get('suspicious_imports', [])

                    for imp_info in suspicious_imports:
                        dll = imp_info.get('dll', '').lower()
                        function = imp_info.get('function', '')

                        if dll and function:
                            import_key = f"{dll}:{function}"
                            if import_key in actual_import_set:
                                validation_result['imports_verified'] += 1
                            else:
                                validation_result['imports_missing'] += 1
                                validation_result['dll_consistency'] = False

            # Calculate validation score
            total_imports = validation_result['imports_verified'] + validation_result['imports_missing']
            if total_imports > 0:
                validation_result['validation_score'] = validation_result['imports_verified'] / total_imports
            else:
                validation_result['validation_score'] = 1.0

            return validation_result

        except Exception as e:
            self.logger.error(f"Import analysis validation failed: {str(e)}")
            return {'error': str(e), 'validation_score': 0.0}

    async def _validate_string_analysis(self, evidence_data: dict[str, Any],
                                      binary_path: Path) -> dict[str, Any]:
        """Validate string analysis evidence against actual binary strings."""
        try:
            validation_result = {
                'strings_verified': 0,
                'strings_missing': 0,
                'encoding_consistency': True,
                'string_location_accuracy': True,
                'validation_score': 0.0
            }

            if not r2pipe:
                return {'error': 'r2pipe not available for string validation'}

            # Get actual strings from binary
            with r2pipe.open(str(binary_path)) as r2:
                actual_strings = r2.cmdj('izj') or []
                actual_string_set = {s.get('string', '') for s in actual_strings if s.get('string')}

                protection_evidence = evidence_data.get('protection_evidence', {})

                for _protection_name, protection_data in protection_evidence.items():
                    string_analysis = protection_data.get('string_analysis', {})
                    suspicious_strings = string_analysis.get('suspicious_strings', [])

                    for string_info in suspicious_strings:
                        string_value = string_info.get('string', '')

                        if string_value in actual_string_set:
                            validation_result['strings_verified'] += 1
                        else:
                            validation_result['strings_missing'] += 1
                            validation_result['string_location_accuracy'] = False

            # Calculate validation score
            total_strings = validation_result['strings_verified'] + validation_result['strings_missing']
            if total_strings > 0:
                validation_result['validation_score'] = validation_result['strings_verified'] / total_strings
            else:
                validation_result['validation_score'] = 1.0

            return validation_result

        except Exception as e:
            self.logger.error(f"String analysis validation failed: {str(e)}")
            return {'error': str(e), 'validation_score': 0.0}

    async def _verify_entropy_analysis(self, evidence_data: dict[str, Any],
                                     binary_path: Path) -> dict[str, Any]:
        """Verify entropy analysis calculations."""
        try:
            verification_result = {
                'entropy_recalculated': False,
                'entropy_matches': True,
                'calculation_accuracy': 1.0,
                'section_entropy_valid': True,
                'verification_score': 0.0
            }

            if not binary_path.exists():
                return {'error': 'Binary file not found for entropy verification'}

            # Read binary data
            binary_data = binary_path.read_bytes()

            # Recalculate entropy
            calculated_entropy = self._calculate_entropy(binary_data)

            protection_evidence = evidence_data.get('protection_evidence', {})
            for _protection_name, protection_data in protection_evidence.items():
                entropy_analysis = protection_data.get('entropy_analysis', {})
                stored_entropy = entropy_analysis.get('overall_entropy', 0.0)

                # Compare calculated vs stored entropy (allow small tolerance)
                entropy_diff = abs(calculated_entropy - stored_entropy)
                if entropy_diff < 0.01:  # 1% tolerance
                    verification_result['entropy_matches'] = True
                    verification_result['calculation_accuracy'] = 1.0 - entropy_diff
                else:
                    verification_result['entropy_matches'] = False
                    verification_result['calculation_accuracy'] = max(0.0, 1.0 - entropy_diff)

            verification_result['entropy_recalculated'] = True
            verification_result['verification_score'] = verification_result['calculation_accuracy']

            return verification_result

        except Exception as e:
            self.logger.error(f"Entropy verification failed: {str(e)}")
            return {'error': str(e), 'verification_score': 0.0}

    async def _validate_cross_references(self, evidence_data: dict[str, Any]) -> dict[str, Any]:
        """Validate cross-references between different evidence types."""
        if not self.config.cross_reference_validation:
            return {'validation_skipped': True}

        try:
            validation_result = {
                'cross_references_found': 0,
                'cross_references_valid': 0,
                'memory_to_disasm_refs': 0,
                'import_to_string_refs': 0,
                'validation_score': 0.0
            }

            protection_evidence = evidence_data.get('protection_evidence', {})

            for _protection_name, protection_data in protection_evidence.items():
                memory_addresses = protection_data.get('memory_addresses', [])
                disassembly_proof = protection_data.get('disassembly_proof', [])
                import_analysis = protection_data.get('import_analysis', {})
                string_analysis = protection_data.get('string_analysis', {})

                # Cross-reference memory addresses with disassembly
                memory_addrs = {addr.get('address', 0) for addr in memory_addresses}
                disasm_addrs = {proof.get('address', 0) for proof in disassembly_proof}

                common_addrs = memory_addrs & disasm_addrs
                validation_result['memory_to_disasm_refs'] += len(common_addrs)
                validation_result['cross_references_found'] += len(common_addrs)
                validation_result['cross_references_valid'] += len(common_addrs)

                # Cross-reference imports with strings
                suspicious_imports = import_analysis.get('suspicious_imports', [])
                suspicious_strings = string_analysis.get('suspicious_strings', [])

                import_names = {imp.get('function', '') for imp in suspicious_imports}
                string_values = {str_info.get('string', '') for str_info in suspicious_strings}

                # Check if any import names appear in strings
                import_string_matches = sum(1 for imp_name in import_names if any(imp_name in s for s in string_values))
                validation_result['import_to_string_refs'] += import_string_matches
                validation_result['cross_references_found'] += import_string_matches
                validation_result['cross_references_valid'] += import_string_matches

            # Calculate validation score
            if validation_result['cross_references_found'] > 0:
                validation_result['validation_score'] = (
                    validation_result['cross_references_valid'] / validation_result['cross_references_found']
                )
            else:
                validation_result['validation_score'] = 1.0  # No cross-references to validate

            return validation_result

        except Exception as e:
            self.logger.error(f"Cross-reference validation failed: {str(e)}")
            return {'error': str(e), 'validation_score': 0.0}

    async def _detect_anomalies(self, evidence_data: dict[str, Any], binary_path: Path) -> list[str]:
        """Detect anomalies in evidence data that might indicate tampering or errors."""
        if not self.config.anomaly_detection_enabled:
            return []

        anomalies = []

        try:
            # Check for impossible memory addresses
            protection_evidence = evidence_data.get('protection_evidence', {})
            for protection_name, protection_data in protection_evidence.items():
                memory_addresses = protection_data.get('memory_addresses', [])

                for addr_info in memory_addresses:
                    addr = addr_info.get('address', 0)
                    if isinstance(addr, str):
                        try:
                            addr = int(addr, 16)
                        except ValueError:
                            anomalies.append(f"Invalid memory address format in {protection_name}: {addr}")
                            continue

                    # Check for suspicious address ranges
                    if addr < 0x400000:  # Below typical PE base address
                        anomalies.append(f"Suspicious low memory address in {protection_name}: {hex(addr)}")
                    elif addr > 0x7FFFFFFF:  # Above 32-bit address space (for 32-bit PEs)
                        if binary_path.exists():
                            # Check if it's actually a 64-bit binary
                            try:
                                header = binary_path.read_bytes()[:1024]
                                if b'PE\x00\x00' in header:
                                    pe_offset = header.find(b'PE\x00\x00')
                                    if pe_offset + 24 < len(header):
                                        machine_type = struct.unpack('<H', header[pe_offset + 4:pe_offset + 6])[0]
                                        if machine_type not in [0x8664, 0xAA64]:  # Not x64 or ARM64
                                            anomalies.append(f"High memory address for 32-bit binary in {protection_name}: {hex(addr)}")
                            except Exception as e:
                                logging.debug(f"Error checking memory address anomaly: {e}")

                # Check for duplicate evidence
                addr_list = [addr_info.get('address', 0) for addr_info in memory_addresses]
                if len(addr_list) != len(set(addr_list)):
                    anomalies.append(f"Duplicate memory addresses found in {protection_name}")

                # Check for empty evidence sections
                if not memory_addresses and not protection_data.get('disassembly_proof'):
                    anomalies.append(f"No memory or disassembly evidence for {protection_name}")

            # Check for timestamp anomalies
            evidence_summary = evidence_data.get('evidence_summary', {})
            collection_time = evidence_summary.get('collection_time', 0)

            for protection_name, protection_data in protection_evidence.items():
                protection_timestamp = protection_data.get('evidence_timestamp', '')
                if protection_timestamp:
                    try:
                        protection_time = datetime.fromisoformat(protection_timestamp.replace('Z', '+00:00'))
                        collection_datetime = datetime.fromtimestamp(collection_time, tz=timezone.utc)

                        if abs((protection_time - collection_datetime).total_seconds()) > 300:  # 5 minutes
                            anomalies.append(f"Timestamp inconsistency for {protection_name}")
                    except Exception:
                        anomalies.append(f"Invalid timestamp format for {protection_name}")

            return anomalies

        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {str(e)}")
            return [f"Anomaly detection error: {str(e)}"]

    def _calculate_integrity_score(self, crypto_verification: dict[str, Any],
                                 temporal_consistency: bool, memory_validation: dict[str, Any],
                                 disassembly_verification: dict[str, Any], import_validation: dict[str, Any],
                                 string_validation: dict[str, Any], entropy_verification: dict[str, Any],
                                 cross_ref_validation: dict[str, Any], anomalies: list[str]) -> float:
        """Calculate overall integrity score from all verification components."""
        try:
            score_components = []
            weights = []

            # Cryptographic verification (weight: 0.25)
            crypto_score = crypto_verification.get('cryptographic_score', 0.0)
            score_components.append(crypto_score)
            weights.append(0.25)

            # Temporal consistency (weight: 0.15)
            temporal_score = 1.0 if temporal_consistency else 0.0
            score_components.append(temporal_score)
            weights.append(0.15)

            # Memory validation (weight: 0.20)
            memory_score = memory_validation.get('validation_score', 0.0)
            score_components.append(memory_score)
            weights.append(0.20)

            # Disassembly verification (weight: 0.15)
            disasm_score = disassembly_verification.get('verification_score', 0.0)
            score_components.append(disasm_score)
            weights.append(0.15)

            # Import validation (weight: 0.10)
            import_score = import_validation.get('validation_score', 0.0)
            score_components.append(import_score)
            weights.append(0.10)

            # String validation (weight: 0.05)
            string_score = string_validation.get('validation_score', 0.0)
            score_components.append(string_score)
            weights.append(0.05)

            # Entropy verification (weight: 0.05)
            entropy_score = entropy_verification.get('verification_score', 0.0)
            score_components.append(entropy_score)
            weights.append(0.05)

            # Cross-reference validation (weight: 0.05)
            cross_ref_score = cross_ref_validation.get('validation_score', 1.0)
            score_components.append(cross_ref_score)
            weights.append(0.05)

            # Calculate weighted average
            if score_components and sum(weights) > 0:
                weighted_score = sum(score * weight for score, weight in zip(score_components, weights, strict=False))
                weighted_score = weighted_score / sum(weights)
            else:
                weighted_score = 0.0

            # Apply anomaly penalty
            anomaly_penalty = min(0.5, len(anomalies) * 0.1)  # Max 50% penalty
            final_score = max(0.0, weighted_score - anomaly_penalty)

            return final_score

        except Exception as e:
            self.logger.error(f"Integrity score calculation failed: {str(e)}")
            return 0.0

    def _determine_authenticity(self, integrity_score: float, anomalies: list[str]) -> bool:
        """Determine if evidence is authentic based on integrity score and anomalies."""
        if integrity_score < self.config.minimum_integrity_threshold:
            return False

        # Check for critical anomalies
        critical_anomalies = [a for a in anomalies if 'suspicious' in a.lower() or 'invalid' in a.lower()]
        if len(critical_anomalies) > 2:
            return False

        return True

    def _assess_confidence(self, integrity_score: float, authenticity_verified: bool) -> str:
        """Assess confidence level in evidence verification."""
        if not authenticity_verified:
            return "NOT_AUTHENTIC"

        if integrity_score >= 0.95:
            return "VERY_HIGH"
        elif integrity_score >= 0.85:
            return "HIGH"
        elif integrity_score >= 0.70:
            return "MEDIUM"
        elif integrity_score >= 0.50:
            return "LOW"
        else:
            return "VERY_LOW"

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                frequency = count / data_len
                entropy -= frequency * (frequency.bit_length() - 1)

        return entropy

    def _calculate_binary_hash(self, binary_path: Path) -> str:
        """Calculate SHA-256 hash of binary file."""
        try:
            if binary_path.exists():
                return hashlib.sha256(binary_path.read_bytes()).hexdigest()
            return ''
        except Exception:
            return ''

    def _calculate_evidence_hash(self, evidence_data: dict[str, Any]) -> str:
        """Calculate hash of evidence data for integrity verification."""
        try:
            # Create deterministic JSON string
            evidence_json = json.dumps(evidence_data, sort_keys=True, separators=(',', ':'))
            return hashlib.sha256(evidence_json.encode('utf-8')).hexdigest()
        except Exception:
            return ''

    def _generate_evidence_id(self, evidence_data: dict[str, Any], binary_path: Path) -> str:
        """Generate unique evidence ID for tracking."""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            binary_name = binary_path.name
            evidence_hash = self._calculate_evidence_hash(evidence_data)[:8]
            return f"EV_{timestamp}_{binary_name}_{evidence_hash}"
        except Exception:
            return f"EV_{timestamp}_unknown"

    def _update_verification_stats(self, authenticity_verified: bool, anomaly_count: int):
        """Update verification statistics."""
        self.verification_stats['total_verifications'] += 1

        if authenticity_verified:
            self.verification_stats['successful_verifications'] += 1
        else:
            self.verification_stats['failed_verifications'] += 1
            self.verification_stats['integrity_violations'] += 1

        self.verification_stats['anomalies_detected'] += anomaly_count

    def get_verification_statistics(self) -> dict[str, Any]:
        """Get current verification statistics."""
        total = self.verification_stats['total_verifications']
        return {
            'verification_stats': self.verification_stats.copy(),
            'success_rate': self.verification_stats['successful_verifications'] / max(1, total),
            'integrity_violation_rate': self.verification_stats['integrity_violations'] / max(1, total),
            'average_anomalies_per_verification': self.verification_stats['anomalies_detected'] / max(1, total)
        }


# Main execution for standalone testing
async def main():
    """Main function for standalone evidence verification testing."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: python evidence_verifier.py <evidence_json_path> <binary_path>")
        return

    evidence_json_path = Path(sys.argv[1])
    binary_path = Path(sys.argv[2])

    if not evidence_json_path.exists():
        print(f"Evidence file not found: {evidence_json_path}")
        return

    if not binary_path.exists():
        print(f"Binary file not found: {binary_path}")
        return

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Load evidence data
    with open(evidence_json_path, encoding='utf-8') as f:
        evidence_data = json.load(f)

    # Create verifier
    config = EvidenceVerificationConfig(
        cryptographic_verification=True,
        deep_binary_analysis=True,
        anomaly_detection_enabled=True
    )
    verifier = EvidenceVerifier(config)

    # Run verification
    print(f"Starting evidence verification for: {binary_path}")
    report = await verifier.verify_evidence_integrity(evidence_data, binary_path)

    # Display results
    print("\n=== EVIDENCE VERIFICATION RESULTS ===")
    print(f"Evidence ID: {report.evidence_id}")
    print(f"Binary: {report.binary_path}")
    print(f"Integrity Score: {report.integrity_score:.3f}")
    print(f"Authenticity Verified: {report.authenticity_verified}")
    print(f"Confidence Assessment: {report.confidence_assessment}")
    print(f"Temporal Consistency: {report.temporal_consistency}")

    if report.anomaly_detection:
        print(f"\nAnomalies Detected ({len(report.anomaly_detection)}):")
        for anomaly in report.anomaly_detection:
            print(f"  - {anomaly}")

    print("\nVerification Statistics:")
    stats = verifier.get_verification_statistics()
    print(f"  - Total Verifications: {stats['verification_stats']['total_verifications']}")
    print(f"  - Success Rate: {stats['success_rate']:.1%}")
    print(f"  - Integrity Violations: {stats['verification_stats']['integrity_violations']}")


if __name__ == "__main__":
    asyncio.run(main())
