"""
Protocol Fingerprinting for Proprietary License Protocols

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
import math
import os
import re
import time
import traceback
from collections import Counter
from typing import Any, Dict, List, Optional, Union

# Import shared entropy calculation
from ...utils.protection.protection_utils import calculate_entropy


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
            'signature_db_path': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'protocol_signatures.json')
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.signatures = {}
        self.learned_signatures = {}
        self.traffic_samples = []

        # License server ports to monitor
        self.license_ports = [
            27000, 27001,  # FlexLM
            1947, 6001,    # HASP/Sentinel
            22350,         # CodeMeter
            2080,          # Autodesk
            8080, 443,     # Adobe
            1688,          # Microsoft KMS
            5093,          # Sentinel RMS
            8224           # Generic license server
        ]

        # Load known signatures
        self._load_signatures()

    def _load_signatures(self):
        """
        Load known protocol signatures from database.
        """
        try:
            if os.path.exists(self.config['signature_db_path']):
                with open(self.config['signature_db_path'], 'r', encoding='utf-8') as f:
                    self.signatures = json.load(f)

                self.logger.info(f"Loaded {len(self.signatures)} protocol signatures")
            else:
                self.logger.info("Signature database not found, initializing with built-in signatures")
                self._initialize_signatures()
                self._save_signatures()

        except (OSError, ValueError, RuntimeError) as e:
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
            with open(self.config['signature_db_path'], 'w', encoding='utf-8') as f:
                json.dump(self.signatures, f, indent=2)

            self.logger.info("Saved %d protocol signatures", len(self.signatures))

        except (OSError, ValueError, RuntimeError) as e:
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
        length = len(data)  # pylint: disable=redefined-outer-name
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
                    for _pattern in signature['patterns']:
                        if 'offset' in _pattern and 'bytes' in _pattern:
                            offset = _pattern['offset']

                            if offset + len(_pattern['bytes']) <= len(packet_data):
                                if _pattern.get('mask') is None:
                                    # Simple pattern match
                                    if packet_data[offset:offset+len(_pattern['bytes'])] == _pattern['bytes']:
                                        confidence += _pattern.get('weight', 0.2)
                                else:
                                    # Masked pattern match
                                    match = True
                                    for _i in range(len(_pattern['bytes'])):
                                        if (_pattern['mask'][_i] & packet_data[offset+_i]) != (_pattern['mask'][_i] & _pattern['bytes'][_i]):
                                            match = False
                                            break

                                    if match:
                                        confidence += _pattern.get('weight', 0.2)

                # Also check for regex pattern matching
                if 'patterns' in signature:
                    pattern_matches = 0
                    regex_patterns = [_p for _p in signature['patterns'] if isinstance(_p, str)]

                    if regex_patterns:
                        for _pattern in regex_patterns:
                            if re.search(_pattern.encode('utf-8') if isinstance(packet_data, bytes) else _pattern, packet_data):
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
                self.logger.info("Identified protocol: %s (confidence: %.2f)", results[0]['name'], results[0]['confidence'])
                return results[0]

            # If no match, try to learn new signature
            if self.config['learning_mode']:
                self._learn_new_signature(packet_data, port)

            return None

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error analyzing traffic: %s", e)

    def fingerprint_packet(self, packet_data: Union[bytes, bytearray], port: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Fingerprint a single packet for protocol identification.

        Args:
            packet_data: Raw packet data
            port: Port number (optional)

        Returns:
            dict: Protocol fingerprint information, or None if not identified
        """
        try:
            self.logger.debug("Fingerprinting packet of %d bytes on port %s", len(packet_data), port)

            # Use the existing analyze_traffic method for actual fingerprinting
            result = self.analyze_traffic(packet_data, port)

            if result:
                # Add fingerprinting specific metadata
                result['fingerprint_timestamp'] = time.time()
                result['packet_size'] = len(packet_data)
                result['source_port'] = port

                # Enhance with packet-specific analysis
                packet_analysis = self._analyze_packet_structure(packet_data)
                result.update(packet_analysis)

                return result

            return None

        except Exception as e:
            self.logger.error("Packet fingerprinting failed: %s", e)
            return None

    def _analyze_packet_structure(self, packet_data: Union[bytes, bytearray]) -> Dict[str, Any]:
        """Analyze packet structure for additional fingerprint information."""
        analysis = {
            'packet_entropy': 0.0,
            'ascii_ratio': 0.0,
            'common_patterns': [],
            'protocol_hints': []
        }

        try:
            # Calculate entropy
            if len(packet_data) > 0:
                byte_counts = [packet_data.count(i) for i in range(256)]
                analysis['packet_entropy'] = -sum(
                    (count / len(packet_data)) * math.log2(count / len(packet_data))
                    for count in byte_counts if count > 0
                )

            # Calculate ASCII ratio
            ascii_bytes = sum(1 for b in packet_data if 32 <= b <= 126)
            analysis['ascii_ratio'] = ascii_bytes / len(packet_data) if packet_data else 0.0

            # Look for common patterns
            if b'HTTP' in packet_data:
                analysis['protocol_hints'].append('HTTP')
            if b'FTP' in packet_data:
                analysis['protocol_hints'].append('FTP')
            if packet_data.startswith(b'\x16\x03'):  # TLS handshake
                analysis['protocol_hints'].append('TLS')
            if b'SSH' in packet_data:
                analysis['protocol_hints'].append('SSH')

            # License-specific patterns
            if any(pattern in packet_data for pattern in [b'license', b'activation', b'key']):
                analysis['protocol_hints'].append('License_Protocol')

        except Exception as e:
            self.logger.debug("Packet structure analysis failed: %s", e)

        return analysis

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

            for _field in header_format:
                field_name = _field['name']
                field_type = _field['type']
                field_length = _field['length']

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

        except (OSError, ValueError, RuntimeError) as e:
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

        except (OSError, ValueError, RuntimeError) as e:
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

            for _sample in self.traffic_samples:
                if _sample['data'] != packet_data:  # Skip self
                    similarity = self._calculate_similarity(packet_data, _sample['data'])
                    if similarity > 0.7:
                        similar_packets.append(_sample)

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

        except (OSError, ValueError, RuntimeError) as e:
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
        for _i in range(min_len):
            if data1[_i] == data2[_i]:
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
        min_len = min(len(_sample['data']) for _sample in samples)

        if min_len < 4:
            return []

        # Find longest common prefix
        prefix_len = 0
        for _i in range(min_len):
            byte_values = set(_sample['data'][_i] for _sample in samples)
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

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Analyze PCAP file for protocol fingerprints.

        This method processes a PCAP capture file to identify and fingerprint
        network protocols, particularly focusing on license-related communications.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            Dictionary containing:
            - file: Path to analyzed file
            - protocols: List of identified protocols
            - fingerprints: Detailed protocol fingerprints
        """
        self.logger.info(f"Analyzing PCAP file: {pcap_path}")

        results = {
            'file': pcap_path,
            'protocols': [],
            'fingerprints': {},
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_packets': 0,
                'license_packets': 0,
                'identified_protocols': 0,
                'new_signatures_learned': 0
            }
        }

        try:
            # Check if file exists
            if not os.path.exists(pcap_path):
                self.logger.error(f"PCAP file not found: {pcap_path}")
                results['error'] = 'File not found'
                return results

            # Try to use pyshark if available
            try:
                import pyshark

                # Open PCAP file
                capture = pyshark.FileCapture(pcap_path, keep_packets=False)

                packets_analyzed = 0
                license_packets = 0
                protocol_counts = Counter()

                # Process packets
                for packet in capture:
                    packets_analyzed += 1

                    # Check for TCP packets
                    if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
                        src_port = int(packet.tcp.srcport)
                        dst_port = int(packet.tcp.dstport)

                        # Check if it's a license port
                        if dst_port in self.license_ports or src_port in self.license_ports:
                            license_packets += 1

                            # Extract payload if available
                            if hasattr(packet.tcp, 'payload'):
                                try:
                                    payload = bytes.fromhex(packet.tcp.payload.replace(':', ''))

                                    # Fingerprint the packet
                                    fingerprint_result = self.fingerprint_packet(payload, dst_port)

                                    if fingerprint_result:
                                        protocol_id = fingerprint_result['protocol_id']
                                        protocol_counts[protocol_id] += 1

                                        # Store detailed fingerprint
                                        if protocol_id not in results['fingerprints']:
                                            results['fingerprints'][protocol_id] = {
                                                'name': fingerprint_result.get('name', protocol_id),
                                                'confidence': fingerprint_result.get('confidence', 0),
                                                'packets': 0,
                                                'ports': set(),
                                                'sample_data': []
                                            }

                                        fp = results['fingerprints'][protocol_id]
                                        fp['packets'] += 1
                                        fp['ports'].add(dst_port)

                                        # Store sample data (limit to 5 samples)
                                        if len(fp['sample_data']) < 5:
                                            fp['sample_data'].append({
                                                'timestamp': float(packet.sniff_timestamp),
                                                'src': f"{packet.ip.src}:{src_port}",
                                                'dst': f"{packet.ip.dst}:{dst_port}",
                                                'size': len(payload),
                                                'entropy': calculate_entropy(payload)
                                            })

                                except Exception as e:
                                    self.logger.debug(f"Error processing packet payload: {e}")

                capture.close()

                # Convert sets to lists for JSON serialization
                for fp in results['fingerprints'].values():
                    fp['ports'] = list(fp['ports'])

                # Update results
                results['protocols'] = list(protocol_counts.keys())
                results['summary']['total_packets'] = packets_analyzed
                results['summary']['license_packets'] = license_packets
                results['summary']['identified_protocols'] = len(results['protocols'])

                self.logger.info(f"PCAP analysis complete: {packets_analyzed} packets, {len(results['protocols'])} protocols identified")

            except ImportError:
                # Fallback to basic PCAP parsing
                self.logger.warning("pyshark not available, using basic PCAP parsing")
                results['error'] = 'Limited analysis - pyshark not available'

                # Basic PCAP file structure parsing
                with open(pcap_path, 'rb') as f:
                    # Read PCAP header
                    pcap_header = f.read(24)
                    if len(pcap_header) < 24:
                        results['error'] = 'Invalid PCAP file'
                        return results

                    # Simple packet counting
                    packet_count = 0
                    while True:
                        # Read packet header
                        packet_header = f.read(16)
                        if len(packet_header) < 16:
                            break

                        # Get packet length
                        packet_len = int.from_bytes(packet_header[8:12], byteorder='little')

                        # Skip packet data
                        f.seek(packet_len, 1)
                        packet_count += 1

                    results['summary']['total_packets'] = packet_count

        except Exception as e:
            self.logger.error(f"Error analyzing PCAP file: {e}")
            self.logger.error(traceback.format_exc())
            results['error'] = str(e)

        return results

    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary for network protocols.

        This method analyzes a binary file to identify hardcoded network protocols,
        license server addresses, and protocol-related strings that indicate
        network-based license verification.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary containing:
            - binary: Path to analyzed file
            - network_functions: List of identified network functions
            - protocols: List of likely protocols used
        """
        self.logger.info(f"Analyzing binary for network protocols: {binary_path}")

        results = {
            'binary': binary_path,
            'network_functions': [],
            'protocols': [],
            'license_indicators': [],
            'network_strings': [],
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'has_network_code': False,
                'likely_license_client': False,
                'protocol_confidence': 0.0
            }
        }

        try:
            # Check if file exists
            if not os.path.exists(binary_path):
                self.logger.error(f"Binary file not found: {binary_path}")
                results['error'] = 'File not found'
                return results

            # Read binary file
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            # 1. Search for network-related function imports
            network_functions = [
                b'socket', b'connect', b'send', b'recv', b'WSAStartup',
                b'getaddrinfo', b'gethostbyname', b'inet_addr',
                b'WinHttpOpen', b'InternetOpen', b'URLDownload',
                b'curl_easy_init', b'SSL_connect', b'TLS_'
            ]

            for func in network_functions:
                if func in binary_data:
                    results['network_functions'].append(func.decode('utf-8', errors='ignore'))

            # 2. Search for protocol-specific strings
            protocol_indicators = {
                'FlexLM': [b'lmgrd', b'flexlm', b'license.dat', b'@', b'SERVER', b'VENDOR', b'FEATURE'],
                'HASP': [b'hasp', b'aksusbd', b'hasplms', b'sentinel', b'1947'],
                'CodeMeter': [b'codemeter', b'cmact', b'wibu', b'22350', b'CmDongle'],
                'Sentinel': [b'sentinel', b'sntlkeyssrvr', b'RMS License Manager', b'5093'],
                'Adobe': [b'adobe_license', b'activation.adobe.com', b'lm.licenses.adobe.com'],
                'Autodesk': [b'adskflex', b'autodesk', b'flexnet', b'2080'],
                'Microsoft KMS': [b'KMSClient', b'SLMgr', b'1688', b'kms.'],
                'Generic': [b'LICENSE', b'ACTIVATION', b'serial', b'product_key', b'registration']
            }

            for protocol, indicators in protocol_indicators.items():
                matches = 0
                for indicator in indicators:
                    if indicator in binary_data:
                        matches += 1

                        # Extract context around the match
                        index = binary_data.find(indicator)
                        start = max(0, index - 20)
                        end = min(len(binary_data), index + len(indicator) + 20)
                        context = binary_data[start:end]

                        results['license_indicators'].append({
                            'protocol': protocol,
                            'indicator': indicator.decode('utf-8', errors='ignore'),
                            'context': context.hex()
                        })

                if matches >= 2:  # At least 2 indicators for confidence
                    results['protocols'].append(protocol)

            # 3. Search for network-related strings
            # Extract ASCII strings
            ascii_strings = re.findall(b'[\x20-\x7e]{4,}', binary_data)

            network_patterns = [
                re.compile(br'(?:https?://|ftp://|tcp://|udp://)[^\s]+'),
                re.compile(br'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),  # IP addresses
                re.compile(br'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}\b'),  # IP:port
                re.compile(br'(?:port|PORT)\s*[=:]\s*[0-9]{1,5}'),
                re.compile(br'(?:server|SERVER)\s*[=:]\s*[^\s]+'),
                re.compile(br'license[_\-]?server', re.IGNORECASE),
                re.compile(br'activation[_\-]?server', re.IGNORECASE)
            ]

            for string in ascii_strings[:1000]:  # Limit to first 1000 strings
                for pattern in network_patterns:
                    if pattern.search(string):
                        decoded = string.decode('utf-8', errors='ignore')
                        if decoded not in results['network_strings']:
                            results['network_strings'].append(decoded)
                        break

            # 4. Check for specific port numbers
            license_ports_bytes = [
                b'\x69\x68',  # 27000 (FlexLM)
                b'\x69\x69',  # 27001 (FlexLM)
                b'\x07\x9b',  # 1947 (HASP)
                b'\x17\x71',  # 6001 (HASP)
                b'\x57\x36',  # 22350 (CodeMeter)
                b'\x08\x20',  # 2080 (License Manager)
                b'\x20\x28',  # 8224 (License Server)
                b'\x13\xd5',  # 5093 (Sentinel)
                b'\x06\x90'   # 1688 (KMS)
            ]

            for port_bytes in license_ports_bytes:
                if port_bytes in binary_data:
                    port_num = int.from_bytes(port_bytes, byteorder='big')
                    self.logger.debug(f"Found license port number: {port_num}")

            # 5. Calculate summary
            results['summary']['has_network_code'] = len(results['network_functions']) > 0
            results['summary']['likely_license_client'] = (
                len(results['protocols']) > 0 or
                len(results['license_indicators']) > 0
            )

            # Calculate confidence
            confidence = 0.0
            if results['network_functions']:
                confidence += 0.3
            if results['protocols']:
                confidence += 0.4
            if results['license_indicators']:
                confidence += 0.3

            results['summary']['protocol_confidence'] = min(confidence, 1.0)

            self.logger.info(
                f"Binary analysis complete: {len(results['network_functions'])} network functions, "
                f"{len(results['protocols'])} protocols identified"
            )

        except Exception as e:
            self.logger.error(f"Error analyzing binary: {e}")
            self.logger.error(traceback.format_exc())
            results['error'] = str(e)

        return results


__all__ = ['ProtocolFingerprinter', 'calculate_entropy']
