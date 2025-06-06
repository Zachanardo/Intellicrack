"""
Protocol Fingerprinting for Proprietary License Protocols

This module provides comprehensive protocol analysis and fingerprinting capabilities
for identifying and understanding proprietary license verification protocols including
FlexLM, HASP/Sentinel, Adobe, Autodesk, and Microsoft KMS protocols.
"""

import json
import logging
import math
import os
import re
import time
import traceback
from collections import Counter
from typing import Any, Dict, List, Optional, Union


# Import shared entropy calculation
from ...utils.protection_utils import calculate_entropy


class ProtocolFingerprinter:
    """
    Protocol fingerprinting for proprietary license protocols.

    This system analyzes network traffic to identify and fingerprint proprietary
    license verification protocols, enabling more effective bypasses.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the protocol fingerprinter.

        Args:
            config: Configuration dictionary (optional)
        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            'min_confidence': 0.7,
            'max_fingerprints': 100,
            'learning_mode': True,
            'analysis_depth': 3,
            'signature_db_path': 'protocol_signatures.json'
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.signatures = {}
        self.learned_signatures = {}
        self.traffic_samples = []

        # Load known signatures
        self._load_signatures()

    def _load_signatures(self):
        """
        Load known protocol signatures from database.
        """
        try:
            if os.path.exists(self.config['signature_db_path']):
                with open(self.config['signature_db_path'], 'r') as f:
                    self.signatures = json.load(f)

                self.logger.info(f"Loaded {len(self.signatures)} protocol signatures")
            else:
                self.logger.info("Signature database not found, initializing with built-in signatures")
                self._initialize_signatures()
                self._save_signatures()

        except Exception as e:
            self.logger.error("Error loading signatures: %s", e)
            self._initialize_signatures()

    def _save_signatures(self):
        """
        Save protocol signatures to database.
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(self.config['signature_db_path'])), exist_ok=True)

            # Save signatures
            with open(self.config['signature_db_path'], 'w') as f:
                json.dump(self.signatures, f, indent=2)

            self.logger.info(f"Saved {len(self.signatures)} protocol signatures")

        except Exception as e:
            self.logger.error("Error saving signatures: %s", e)

    def _initialize_signatures(self):
        """
        Initialize with built-in protocol signatures.
        """
        # FlexLM protocol
        self.signatures['flexlm'] = {
            'name': 'FlexLM',
            'description': 'Flexible License Manager by Flexera',
            'ports': [27000, 27001, 1101],
            'patterns': [
                {'offset': 0, 'bytes': b'VENDOR_', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'SERVER_', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'FEATURE', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'INCREMENT', 'mask': None, 'weight': 0.5}
            ],
            'header_format': [
                {'name': 'command', 'type': 'string', 'length': 8},
                {'name': 'version', 'type': 'uint16', 'length': 2},
                {'name': 'payload_length', 'type': 'uint16', 'length': 2}
            ],
            'response_templates': {
                'heartbeat': b'SERVER_HEARTBEAT\x00\x01\x00\x00',
                'license_ok': b'FEATURE_RESPONSE\x00\x01\x00\x01\x01'
            }
        }

        # HASP/Sentinel protocol
        self.signatures['hasp'] = {
            'name': 'HASP/Sentinel',
            'description': 'Hardware key protection by Thales',
            'ports': [1947],
            'patterns': [
                {'offset': 0, 'bytes': b'HASP_', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'SENTINEL_', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'\x00\x01\x02\x03\x04', 'mask': None, 'weight': 0.3}
            ],
            'header_format': [
                {'name': 'signature', 'type': 'bytes', 'length': 4},
                {'name': 'command', 'type': 'uint8', 'length': 1},
                {'name': 'payload_length', 'type': 'uint16', 'length': 2}
            ],
            'response_templates': {
                'heartbeat': b'\x00\x01\x02\x03\x00\x00\x00',
                'license_ok': b'\x00\x01\x02\x03\x01\x00\x01\x01'
            }
        }

        # Adobe licensing protocol
        self.signatures['adobe'] = {
            'name': 'Adobe Licensing',
            'description': 'Adobe Creative Cloud licensing protocol',
            'ports': [443, 8080],
            'patterns': [
                {'offset': 0, 'bytes': b'LCSAP', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'ADOBE_LICENSE', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'{"licensing":', 'mask': None, 'weight': 0.3}
            ],
            'header_format': [
                {'name': 'signature', 'type': 'string', 'length': 5},
                {'name': 'version', 'type': 'uint8', 'length': 1},
                {'name': 'command', 'type': 'uint8', 'length': 1},
                {'name': 'payload_length', 'type': 'uint16', 'length': 2}
            ],
            'response_templates': {
                'heartbeat': b'LCSAP\x01\x00\x00\x00',
                'license_ok': b'LCSAP\x01\x01\x00\x01\x01'
            }
        }

        # Autodesk licensing protocol
        self.signatures['autodesk'] = {
            'name': 'Autodesk Licensing',
            'description': 'Autodesk product licensing protocol',
            'ports': [2080, 443],
            'patterns': [
                {'offset': 0, 'bytes': b'ADSK', 'mask': None, 'weight': 0.5},
                {'offset': 0, 'bytes': b'{"license":', 'mask': None, 'weight': 0.3}
            ],
            'header_format': [
                {'name': 'signature', 'type': 'string', 'length': 4},
                {'name': 'version', 'type': 'uint8', 'length': 1},
                {'name': 'command', 'type': 'uint8', 'length': 1},
                {'name': 'payload_length', 'type': 'uint16', 'length': 2}
            ],
            'response_templates': {
                'heartbeat': b'ADSK\x01\x00\x00\x00',
                'license_ok': b'ADSK\x01\x01\x00\x01\x01'
            }
        }

        # Microsoft KMS protocol
        self.signatures['microsoft_kms'] = {
            'name': 'Microsoft KMS',
            'description': 'Microsoft Key Management Service protocol',
            'ports': [1688],
            'patterns': [
                {'offset': 0, 'bytes': b'\x00\x00\x00\x00\x00\x00\x00\x00', 'mask': None, 'weight': 0.2},
                {'offset': 40, 'bytes': b'KMSV', 'mask': None, 'weight': 0.5}
            ],
            'header_format': [
                {'name': 'signature', 'type': 'bytes', 'length': 8},
                {'name': 'protocol', 'type': 'uint16', 'length': 2},
                {'name': 'payload_length', 'type': 'uint16', 'length': 2}
            ],
            'response_templates': {
                'license_ok': b'\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00KMSV\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            }
        }

    def _calculate_byte_frequency(self, data: Union[bytes, bytearray]) -> Dict[int, float]:
        """
        Calculate the frequency distribution of bytes in the given data.

        Args:
            data: Binary data to analyze

        Returns:
            dict: Mapping of byte values to their frequency (0.0 to 1.0)
        """
        length = len(data)
        if length == 0:
            return {}

        counts = Counter(data)
        freq = {byte: count / length for byte, count in counts.items()}
        return freq

    def analyze_traffic(self, packet_data: Union[bytes, bytearray], port: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Analyze network traffic to identify license protocols.

        Args:
            packet_data: Raw packet data
            port: Port number (optional)

        Returns:
            dict: Identified protocol information, or None if not identified
        """
        try:
            # Store traffic sample for learning
            if self.config['learning_mode']:
                self.traffic_samples.append({
                    'data': packet_data,
                    'port': port,
                    'timestamp': time.time()
                })

                # Trim samples if needed
                if len(self.traffic_samples) > 1000:
                    self.traffic_samples = self.traffic_samples[-1000:]

            # Check each signature
            results = []

            for protocol_id, signature in self.signatures.items():
                confidence = 0.0

                # Check port if provided
                if port is not None and port in signature['ports']:
                    confidence += 0.2

                # Check statistical features if defined
                if 'statistical_features' in signature:
                    # Calculate entropy
                    entropy = calculate_entropy(packet_data)

                    # Calculate byte frequency distribution
                    byte_freq = self._calculate_byte_frequency(packet_data)

                    # Check entropy range
                    if (entropy > signature['statistical_features'].get('min_entropy', 0) and
                        entropy < signature['statistical_features'].get('max_entropy', 8)):
                        confidence += 0.3

                    # Check byte frequency distribution if defined
                    if 'byte_freq_thresholds' in signature['statistical_features']:
                        freq_matches = 0
                        total_checks = 0

                        for byte_val, (min_freq, max_freq) in signature['statistical_features']['byte_freq_thresholds'].items():
                            byte_val = int(byte_val) if isinstance(byte_val, str) else byte_val
                            total_checks += 1

                            if byte_val in byte_freq:
                                if min_freq <= byte_freq[byte_val] <= max_freq:
                                    freq_matches += 1

                        if total_checks > 0:
                            confidence += 0.3 * (freq_matches / total_checks)

                # Check patterns
                # First check for binary pattern matching
                if 'patterns' in signature:
                    for pattern in signature['patterns']:
                        if 'offset' in pattern and 'bytes' in pattern:
                            offset = pattern['offset']

                            if offset + len(pattern['bytes']) <= len(packet_data):
                                if pattern.get('mask') is None:
                                    # Simple pattern match
                                    if packet_data[offset:offset+len(pattern['bytes'])] == pattern['bytes']:
                                        confidence += pattern.get('weight', 0.2)
                                else:
                                    # Masked pattern match
                                    match = True
                                    for i in range(len(pattern['bytes'])):
                                        if (pattern['mask'][i] & packet_data[offset+i]) != (pattern['mask'][i] & pattern['bytes'][i]):
                                            match = False
                                            break

                                    if match:
                                        confidence += pattern.get('weight', 0.2)

                # Also check for regex pattern matching
                if 'patterns' in signature:
                    pattern_matches = 0
                    regex_patterns = [p for p in signature['patterns'] if isinstance(p, str)]

                    if regex_patterns:
                        for pattern in regex_patterns:
                            if re.search(pattern.encode('utf-8') if isinstance(packet_data, bytes) else pattern, packet_data):
                                pattern_matches += 1

                        # Calculate match percentage for regex patterns
                        if len(regex_patterns) > 0:
                            match_ratio = pattern_matches / len(regex_patterns)
                            if match_ratio >= 0.7:  # 70% match threshold
                                confidence += 0.5
                            else:
                                confidence += 0.3 * match_ratio

                if confidence >= self.config['min_confidence']:
                    results.append({
                        'protocol_id': protocol_id,
                        'name': signature['name'],
                        'description': signature['description'],
                        'confidence': confidence,
                        'header_format': signature['header_format'],
                        'response_templates': signature['response_templates']
                    })

            # Sort by confidence
            results.sort(key=lambda x: x['confidence'], reverse=True)

            if results:
                self.logger.info(f"Identified protocol: {results[0]['name']} (confidence: {results[0]['confidence']:.2f})")
                return results[0]

            # If no match, try to learn new signature
            if self.config['learning_mode']:
                self._learn_new_signature(packet_data, port)

            return None

        except Exception as e:
            self.logger.error("Error analyzing traffic: %s", e)
            self.logger.error(traceback.format_exc())
            return None

    def parse_packet(self, protocol_id: str, packet_data: Union[bytes, bytearray]) -> Optional[Dict[str, Any]]:
        """
        Parse a packet according to the protocol's header format.

        Args:
            protocol_id: Protocol identifier
            packet_data: Raw packet data

        Returns:
            dict: Parsed packet fields, or None if parsing failed
        """
        try:
            if protocol_id not in self.signatures:
                return None

            signature = self.signatures[protocol_id]
            header_format = signature['header_format']

            result = {}
            offset = 0

            for field in header_format:
                field_name = field['name']
                field_type = field['type']
                field_length = field['length']

                if offset + field_length > len(packet_data):
                    return None

                if field_type == 'uint8':
                    result[field_name] = packet_data[offset]
                elif field_type == 'uint16':
                    result[field_name] = int.from_bytes(packet_data[offset:offset+field_length], byteorder='big')
                elif field_type == 'uint32':
                    result[field_name] = int.from_bytes(packet_data[offset:offset+field_length], byteorder='big')
                elif field_type == 'string':
                    result[field_name] = packet_data[offset:offset+field_length].decode('utf-8', errors='ignore').rstrip('\x00')
                elif field_type == 'bytes':
                    result[field_name] = packet_data[offset:offset+field_length]

                offset += field_length

            # Add payload
            if offset < len(packet_data):
                result['payload'] = packet_data[offset:]

            return result

        except Exception as e:
            self.logger.error("Error parsing packet: %s", e)
            return None

    def generate_response(self, protocol_id: str, request_packet: Union[bytes, bytearray],
                         response_type: str = 'license_ok') -> Optional[bytes]:
        """
        Generate a response packet for a license check request.

        Args:
            protocol_id: Protocol identifier
            request_packet: Request packet data
            response_type: Type of response to generate

        Returns:
            bytes: Response packet data, or None if generation failed
        """
        try:
            if protocol_id not in self.signatures:
                return None

            signature = self.signatures[protocol_id]

            if response_type not in signature['response_templates']:
                response_type = next(iter(signature['response_templates']))

            response_template = signature['response_templates'][response_type]

            # Parse request packet
            parsed_request = self.parse_packet(protocol_id, request_packet)

            if not parsed_request:
                return response_template

            # Customize response based on request
            response = bytearray(response_template)

            # Copy request fields that should be echoed back
            if protocol_id == 'flexlm' and len(response) >= 4 and len(request_packet) >= 4:
                # Copy version field
                response[2:4] = request_packet[2:4]

            elif protocol_id == 'hasp' and len(response) >= 7 and len(request_packet) >= 7:
                # Copy signature field
                response[0:4] = request_packet[0:4]

            elif protocol_id == 'adobe' and len(response) >= 5 and len(request_packet) >= 5:
                # Copy signature and version fields
                response[0:6] = request_packet[0:6]

            elif protocol_id == 'autodesk' and len(response) >= 6 and len(request_packet) >= 6:
                # Copy signature and version fields
                response[0:5] = request_packet[0:5]

            elif protocol_id == 'microsoft_kms' and len(response) >= 12 and len(request_packet) >= 12:
                # Copy signature and protocol fields
                response[0:10] = request_packet[0:10]

            return bytes(response)

        except Exception as e:
            self.logger.error("Error generating response: %s", e)
            return None

    def _learn_new_signature(self, packet_data: Union[bytes, bytearray], port: Optional[int] = None) -> bool:
        """
        Attempt to learn a new protocol signature from traffic.

        Args:
            packet_data: Raw packet data
            port: Port number (optional)

        Returns:
            bool: True if a new signature was learned, False otherwise
        """
        try:
            # Need at least 10 samples to learn
            if len(self.traffic_samples) < 10:
                return False

            # Find similar packets
            similar_packets = []

            for sample in self.traffic_samples:
                if sample['data'] != packet_data:  # Skip self
                    similarity = self._calculate_similarity(packet_data, sample['data'])
                    if similarity > 0.7:
                        similar_packets.append(sample)

            if len(similar_packets) < 3:
                return False

            # Extract common patterns
            patterns = self._extract_common_patterns(similar_packets)

            if not patterns:
                return False

            # Create new signature
            signature_id = f"learned_{len(self.learned_signatures) + 1}"

            signature = {
                'name': f"Learned Protocol {len(self.learned_signatures) + 1}",
                'description': "Automatically learned protocol signature",
                'ports': [port] if port else [],
                'patterns': patterns,
                'header_format': [
                    {'name': 'signature', 'type': 'bytes', 'length': len(patterns[0]['bytes'])},
                    {'name': 'payload', 'type': 'bytes', 'length': 0}  # Variable length
                ],
                'response_templates': {
                    'license_ok': b'\x01' * 8  # Generic positive response
                }
            }

            # Add to learned signatures
            self.learned_signatures[signature_id] = signature

            # Add to active signatures
            self.signatures[signature_id] = signature

            # Save signatures
            self._save_signatures()

            self.logger.info("Learned new protocol signature: %s", signature_id)
            return True

        except Exception as e:
            self.logger.error("Error learning new signature: %s", e)
            return False

    def _calculate_similarity(self, data1: Union[bytes, bytearray], data2: Union[bytes, bytearray]) -> float:
        """
        Calculate similarity between two data samples.

        Args:
            data1: First data sample
            data2: Second data sample

        Returns:
            float: Similarity score (0.0 to 1.0)
        """
        # Simple similarity based on common bytes
        min_len = min(len(data1), len(data2))
        max_len = max(len(data1), len(data2))

        if min_len == 0:
            return 0.0

        common_bytes = 0
        for i in range(min_len):
            if data1[i] == data2[i]:
                common_bytes += 1

        return common_bytes / max_len

    def _extract_common_patterns(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract common patterns from similar packets.

        Args:
            samples: List of similar packet samples

        Returns:
            list: List of pattern dictionaries
        """
        # Extract common prefix
        min_len = min(len(sample['data']) for sample in samples)

        if min_len < 4:
            return []

        # Find longest common prefix
        prefix_len = 0
        for i in range(min_len):
            byte_values = set(sample['data'][i] for sample in samples)
            if len(byte_values) == 1:
                prefix_len += 1
            else:
                break

        if prefix_len < 2:
            return []

        # Create pattern from prefix
        prefix_bytes = samples[0]['data'][:prefix_len]

        return [
            {'offset': 0, 'bytes': prefix_bytes, 'mask': None, 'weight': 0.5}
        ]


__all__ = ['ProtocolFingerprinter', 'calculate_entropy']
