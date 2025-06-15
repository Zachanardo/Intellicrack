"""
Dynamic Response Generator for License Server Protocols

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

import hashlib
import json
import logging
import re
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ResponseContext:
    """Context information for response generation"""
    source_ip: str
    source_port: int
    target_host: str
    target_port: int
    protocol_type: str
    request_data: bytes
    parsed_request: Optional[Dict[str, Any]]
    client_fingerprint: str
    timestamp: float
@dataclass
class GeneratedResponse:
    """Container for generated response data"""
    response_data: bytes
    response_type: str
    generation_method: str
    confidence: float
    metadata: Dict[str, Any]


class FlexLMProtocolHandler:
    """Handler for FlexLM license protocol"""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.FlexLMHandler")

    def parse_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse FlexLM license request"""
        try:
            text_data = data.decode('utf-8', errors='ignore')

            # Look for FlexLM command patterns
            request_info = {
                'command': 'unknown',
                'features': [],
                'version': None,
                'hostid': None,
                'vendor': None
            }

            # Parse FEATURE lines
            for line in text_data.split('\n'):
                line = line.strip()

                if line.startswith('FEATURE'):
                    parts = line.split()
                    if len(parts) >= 4:
                        request_info['features'].append({
                            'name': parts[1],
                            'vendor': parts[2],
                            'version': parts[3]
                        })

                elif line.startswith('SERVER'):
                    parts = line.split()
                    if len(parts) >= 2:
                        request_info['hostid'] = parts[2] if len(parts) > 2 else None

                elif line.startswith('VENDOR'):
                    parts = line.split()
                    if len(parts) >= 2:
                        request_info['vendor'] = parts[1]

            return request_info

        except Exception as e:
            self.logger.debug(f"FlexLM parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate FlexLM license response"""
        try:
            parsed = self.parse_request(context.request_data)

            # Generate valid FlexLM response
            response_lines = []

            # Server line
            response_lines.append("SERVER this_host ANY 27000")

            # Vendor line
            vendor = parsed.get('vendor', 'vendor') if parsed else 'vendor'
            response_lines.append(f"VENDOR {vendor}")

            # Feature lines
            if parsed and parsed.get('features'):
                for feature in parsed['features']:
                    feature_line = (
                        f"FEATURE {feature['name']} {feature['vendor']} "
                        f"{feature['version']} permanent uncounted "
                        f"HOSTID=ANY SIGN=VALID ck=123"
                    )
                    response_lines.append(feature_line)
            else:
                # Default feature
                response_lines.append(
                    "FEATURE product vendor 1.0 permanent uncounted "
                    "HOSTID=ANY SIGN=VALID ck=123"
                )

            response_text = '\n'.join(response_lines) + '\n'
            return response_text.encode('utf-8')

        except Exception as e:
            self.logger.error(f"FlexLM response generation error: {e}")
            return b"SERVER this_host ANY 27000\nVENDOR vendor\nFEATURE product vendor 1.0 permanent uncounted HOSTID=ANY SIGN=VALID\n"


class HASPProtocolHandler:
    """Handler for HASP/Sentinel license protocol"""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.HASPHandler")

    def parse_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HASP license request"""
        try:
            # Check if it's JSON format
            if data.startswith(b'{'):
                json_data = json.loads(data.decode('utf-8'))
                return {
                    'format': 'json',
                    'data': json_data
                }

            # Check if it's binary format
            if len(data) >= 4:
                header = struct.unpack('<I', data[:4])[0]
                return {
                    'format': 'binary',
                    'header': header,
                    'data': data[4:]
                }

            return {
                'format': 'text',
                'data': data.decode('utf-8', errors='ignore')
            }

        except Exception as e:
            self.logger.debug(f"HASP parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate HASP license response"""
        try:
            parsed = self.parse_request(context.request_data)

            if parsed and parsed.get('format') == 'json':
                # JSON response
                response = {
                    "status": "OK",
                    "key": "VALID",
                    "expiration": "permanent",
                    "features": ["all"],
                    "timestamp": int(time.time()),
                    "session_id": str(uuid.uuid4())
                }
                return json.dumps(response).encode('utf-8')

            elif parsed and parsed.get('format') == 'binary':
                # Binary response
                response_header = struct.pack('<I', 0x12345678)  # Valid response header
                response_data = b'\x01\x00\x00\x00'  # Success code
                return response_header + response_data

            else:
                # Text response
                return b'HASP_STATUS_OK'

        except Exception as e:
            self.logger.error(f"HASP response generation error: {e}")
            return b'{"status":"OK","key":"VALID","expiration":"permanent"}'
class AdobeProtocolHandler:
    """Handler for Adobe license protocol"""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.AdobeHandler")

    def parse_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Adobe license request"""
        try:
            text_data = data.decode('utf-8', errors='ignore')

            # Look for Adobe activation patterns
            request_info = {
                'type': 'unknown',
                'product': None,
                'serial': None,
                'machine_id': None
            }

            # Parse JSON if present
            if '{' in text_data and '}' in text_data:
                try:
                    json_start = text_data.find('{')
                    json_end = text_data.rfind('}') + 1
                    json_str = text_data[json_start:json_end]
                    json_data = json.loads(json_str)

                    request_info.update({
                        'type': 'json',
                        'data': json_data
                    })

                    # Extract common fields
                    if 'serial' in json_data:
                        request_info['serial'] = json_data['serial']
                    if 'product' in json_data:
                        request_info['product'] = json_data['product']

                except json.JSONDecodeError:
                    pass

            # Look for activation patterns
            if 'activate' in text_data.lower():
                request_info['type'] = 'activation'
            elif 'deactivate' in text_data.lower():
                request_info['type'] = 'deactivation'
            elif 'verify' in text_data.lower():
                request_info['type'] = 'verification'

            return request_info

        except Exception as e:
            self.logger.debug(f"Adobe parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Adobe license response"""
        try:
            parsed = self.parse_request(context.request_data)

            # Generate Adobe activation response
            if parsed and parsed.get('type') == 'json':
                response = {
                    "status": "SUCCESS",
                    "message": "License is valid",
                    "expiry": "never",
                    "serial": parsed.get('serial', '1234-5678-9012-3456-7890'),
                    "activation_id": str(uuid.uuid4()),
                    "timestamp": time.time()
                }
                return json.dumps(response).encode('utf-8')

            elif parsed and parsed.get('type') == 'activation':
                # XML-style response
                response = f"""<?xml version="1.0"?>
<activationResponse>
    <status>SUCCESS</status>
    <activationId>{uuid.uuid4()}</activationId>
    <expiry>never</expiry>
    <features>all</features>
</activationResponse>"""
                return response.encode('utf-8')

            else:
                # Simple text response
                return b'ACTIVATION_SUCCESS'

        except Exception as e:
            self.logger.error(f"Adobe response generation error: {e}")
            return b'{"status":"SUCCESS","message":"License is valid","expiry":"never"}'


class MicrosoftKMSHandler:
    """Handler for Microsoft KMS protocol"""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.KMSHandler")

    def parse_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Microsoft KMS request"""
        try:
            # KMS uses RPC protocol
            if len(data) >= 16:
                # Parse RPC header
                header = struct.unpack('<IIII', data[:16])
                return {
                    'format': 'rpc',
                    'version': header[0],
                    'packet_type': header[1],
                    'fragment_flags': header[2],
                    'data_length': header[3],
                    'payload': data[16:]
                }

            # Fallback to text parsing
            text_data = data.decode('utf-8', errors='ignore')
            return {
                'format': 'text',
                'data': text_data
            }

        except Exception as e:
            self.logger.debug(f"KMS parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Microsoft KMS response"""
        try:
            parsed = self.parse_request(context.request_data)

            if parsed and parsed.get('format') == 'rpc':
                # Generate RPC response
                response_header = struct.pack('<IIII', 5, 2, 3, 32)  # Version, response type, flags, length
                response_payload = b'\x00' * 32  # Success response
                return response_header + response_payload

            else:
                # Simple activation response
                return b'KMS_ACTIVATION_SUCCESS'

        except Exception as e:
            self.logger.error(f"KMS response generation error: {e}")
            return b'\x00\x00\x00\x00\x00\x00\x00\x00' * 4


class AutodeskProtocolHandler:
    """Handler for Autodesk license protocol"""

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.AutodeskHandler")

    def parse_request(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse Autodesk license request"""
        try:
            text_data = data.decode('utf-8', errors='ignore')

            request_info = {
                'type': 'unknown',
                'product': None,
                'version': None
            }

            # Look for Autodesk patterns
            if 'AdskNetworkLicenseManager' in text_data:
                request_info['type'] = 'network_license'

            # Parse JSON if present
            if '{' in text_data:
                try:
                    json_start = text_data.find('{')
                    json_end = text_data.rfind('}') + 1
                    json_str = text_data[json_start:json_end]
                    json_data = json.loads(json_str)
                    request_info.update(json_data)
                except json.JSONDecodeError:
                    pass

            return request_info

        except Exception as e:
            self.logger.debug(f"Autodesk parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Autodesk license response"""
        try:
            # Log context information for debugging
            self.logger.debug(f"Generating Autodesk response for {context.source_ip}:{context.source_port}")

            # Parse context request if available
            parsed_request = context.parsed_request or self.parse_request(context.request_data)

            response = {
                "status": "success",
                "license": {
                    "status": "ACTIVATED",
                    "type": "PERMANENT",
                    "expiry": "never",
                    "features": ["all"]
                },
                "timestamp": time.time(),
                "client_id": context.client_fingerprint[:16]  # Include client fingerprint
            }

            # Customize response based on parsed request
            if parsed_request:
                if parsed_request.get('product'):
                    response['license']['product'] = parsed_request['product']
                if parsed_request.get('version'):
                    response['license']['version'] = parsed_request['version']

            return json.dumps(response).encode('utf-8')

        except Exception as e:
            self.logger.error(f"Autodesk response generation error for {context.source_ip}: {e}")
            return b'{"status":"success","license":{"status":"ACTIVATED","type":"PERMANENT"}}'
class DynamicResponseGenerator:
    """
    Dynamic response generator for license server protocols.
    
    This class analyzes incoming license requests and generates appropriate
    responses based on the detected protocol and request content.
    """

    def __init__(self):
        """Initialize the dynamic response generator"""
        self.logger = logging.getLogger("IntellicrackLogger.ResponseGenerator")

        # Protocol handlers
        self.handlers = {
            'flexlm': FlexLMProtocolHandler(),
            'hasp': HASPProtocolHandler(),
            'adobe': AdobeProtocolHandler(),
            'microsoft': MicrosoftKMSHandler(),
            'autodesk': AutodeskProtocolHandler()
        }

        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'protocols_handled': {},
            'average_response_time': 0.0
        }

        # Learning data
        self.learned_patterns: Dict[str, List[Dict[str, Any]]] = {}
        self.response_cache: Dict[str, Tuple[bytes, float]] = {}
        self.cache_ttl = 300  # 5 minutes

    def generate_response(self, context: ResponseContext) -> GeneratedResponse:
        """
        Generate a response for the given context.
        
        Args:
            context: Request context information
            
        Returns:
            GeneratedResponse: Generated response data
        """
        start_time = time.time()

        try:
            self.stats['total_requests'] += 1

            # Check cache first
            cache_key = self._generate_cache_key(context)
            cached_response = self._get_cached_response(cache_key)
            if cached_response:
                return GeneratedResponse(
                    response_data=cached_response,
                    response_type='cached',
                    generation_method='cache_lookup',
                    confidence=1.0,
                    metadata={'cache_hit': True}
                )

            # Try protocol-specific handler
            if context.protocol_type in self.handlers:
                handler = self.handlers[context.protocol_type]
                response_data = handler.generate_response(context)

                # Cache the response
                self._cache_response(cache_key, response_data)

                # Update statistics
                self.stats['successful_responses'] += 1
                if context.protocol_type not in self.stats['protocols_handled']:
                    self.stats['protocols_handled'][context.protocol_type] = 0
                self.stats['protocols_handled'][context.protocol_type] += 1

                # Learn from this request
                self._learn_from_request(context, response_data)

                return GeneratedResponse(
                    response_data=response_data,
                    response_type='protocol_specific',
                    generation_method=f'{context.protocol_type}_handler',
                    confidence=0.9,
                    metadata={
                        'protocol': context.protocol_type,
                        'request_size': len(context.request_data)
                    }
                )

            # Try adaptive generation based on learned patterns
            adaptive_response = self._generate_adaptive_response(context)
            if adaptive_response:
                self._cache_response(cache_key, adaptive_response)
                self.stats['successful_responses'] += 1

                return GeneratedResponse(
                    response_data=adaptive_response,
                    response_type='adaptive',
                    generation_method='pattern_learning',
                    confidence=0.7,
                    metadata={'adaptive': True}
                )

            # Fallback to generic response
            generic_response = self._generate_generic_response(context)
            self._cache_response(cache_key, generic_response)
            self.stats['successful_responses'] += 1

            return GeneratedResponse(
                response_data=generic_response,
                response_type='generic',
                generation_method='fallback',
                confidence=0.5,
                metadata={'fallback': True}
            )

        except Exception as e:
            self.logger.error(f"Response generation error: {e}")
            self.stats['failed_responses'] += 1

            # Return error response
            return GeneratedResponse(
                response_data=b'ERROR',
                response_type='error',
                generation_method='error_fallback',
                confidence=0.0,
                metadata={'error': str(e)}
            )

        finally:
            # Update average response time
            response_time = time.time() - start_time
            current_avg = self.stats['average_response_time']
            total_requests = self.stats['total_requests']
            self.stats['average_response_time'] = (current_avg * (total_requests - 1) + response_time) / total_requests

    def _generate_cache_key(self, context: ResponseContext) -> str:
        """Generate cache key for request"""
        key_data = f"{context.protocol_type}:{context.target_port}:{hashlib.md5(context.request_data).hexdigest()}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def _get_cached_response(self, cache_key: str) -> Optional[bytes]:
        """Get cached response if still valid"""
        if cache_key in self.response_cache:
            response_data, timestamp = self.response_cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                return response_data
            else:
                # Remove expired cache entry
                del self.response_cache[cache_key]
        return None

    def _cache_response(self, cache_key: str, response_data: bytes):
        """Cache response data"""
        self.response_cache[cache_key] = (response_data, time.time())

        # Limit cache size
        if len(self.response_cache) > 1000:
            # Remove oldest entries
            sorted_items = sorted(self.response_cache.items(), key=lambda x: x[1][1])
            for old_key, _ in sorted_items[:100]:
                del self.response_cache[old_key]

    def _learn_from_request(self, context: ResponseContext, response_data: bytes):
        """Learn patterns from successful request/response pairs"""
        try:
            protocol = context.protocol_type
            if protocol not in self.learned_patterns:
                self.learned_patterns[protocol] = []

            # Extract patterns from request
            request_patterns = self._extract_patterns(context.request_data)
            response_patterns = self._extract_patterns(response_data)

            learning_entry = {
                'timestamp': context.timestamp,
                'request_patterns': request_patterns,
                'response_patterns': response_patterns,
                'request_size': len(context.request_data),
                'response_size': len(response_data),
                'source_port': context.source_port,
                'target_port': context.target_port
            }

            self.learned_patterns[protocol].append(learning_entry)

            # Limit learning data size
            if len(self.learned_patterns[protocol]) > 100:
                self.learned_patterns[protocol].pop(0)

        except Exception as e:
            self.logger.debug(f"Learning error: {e}")

    def _extract_patterns(self, data: bytes) -> List[str]:
        """Extract patterns from data for learning"""
        patterns = []

        try:
            # Convert to text for pattern extraction
            text_data = data.decode('utf-8', errors='ignore')

            # Extract JSON patterns
            json_matches = re.findall(r'\{[^}]*\}', text_data)
            patterns.extend(json_matches)

            # Extract key-value patterns
            kv_matches = re.findall(r'(\w+)[:=]([^\s,}]+)', text_data)
            patterns.extend([f"{k}:{v}" for k, v in kv_matches])

            # Extract common words
            words = re.findall(r'\b[A-Za-z]{3,}\b', text_data)
            patterns.extend(words[:10])  # Limit to first 10 words

            # Extract hex patterns from binary data
            if len(data) >= 4:
                hex_header = data[:4].hex()
                patterns.append(f"hex:{hex_header}")

        except Exception:
            pass

        return patterns[:20]  # Limit pattern count

    def _generate_adaptive_response(self, context: ResponseContext) -> Optional[bytes]:
        """Generate response based on learned patterns"""
        try:
            protocol = context.protocol_type
            if protocol not in self.learned_patterns:
                return None

            # Find similar requests
            request_patterns = self._extract_patterns(context.request_data)
            best_match = None
            best_score = 0

            for learned_entry in self.learned_patterns[protocol]:
                score = self._calculate_similarity(request_patterns, learned_entry['request_patterns'])
                if score > best_score:
                    best_score = score
                    best_match = learned_entry

            # Use best match if similarity is high enough
            if best_match and best_score > 0.5:
                # Generate response based on learned response patterns
                return self._synthesize_response(best_match['response_patterns'], context)

        except Exception as e:
            self.logger.debug(f"Adaptive generation error: {e}")

        return None

    def _calculate_similarity(self, patterns1: List[str], patterns2: List[str]) -> float:
        """Calculate similarity between pattern lists"""
        if not patterns1 or not patterns2:
            return 0.0

        matches = sum(1 for p in patterns1 if p in patterns2)
        total = len(set(patterns1 + patterns2))

        return matches / total if total > 0 else 0.0

    def _synthesize_response(self, response_patterns: List[str], context: ResponseContext) -> bytes:
        """Synthesize response from learned patterns"""
        try:
            # Look for JSON patterns
            json_patterns = [p for p in response_patterns if p.startswith('{')]
            if json_patterns:
                # Use first JSON pattern as template
                template = json_patterns[0]

                # Replace placeholders with context-specific values
                response_text = template.replace('timestamp', str(int(context.timestamp)))
                response_text = response_text.replace('uuid', str(uuid.uuid4()))

                return response_text.encode('utf-8')

            # Look for key-value patterns
            kv_patterns = [p for p in response_patterns if ':' in p]
            if kv_patterns:
                # Build simple response
                response_dict = {}
                for pattern in kv_patterns:
                    if ':' in pattern:
                        key, value = pattern.split(':', 1)
                        response_dict[key] = value

                return json.dumps(response_dict).encode('utf-8')

            # Fallback to simple text response
            return b'OK'

        except Exception as e:
            self.logger.debug(f"Response synthesis error: {e}")
            return b'OK'

    def _generate_generic_response(self, context: ResponseContext) -> bytes:
        """Generate generic response based on request characteristics"""
        try:
            # Analyze request data for clues
            request_text = context.request_data.decode('utf-8', errors='ignore').lower()

            # JSON-style response
            if '{' in request_text or 'json' in request_text:
                response = {
                    "status": "OK",
                    "license": "valid",
                    "timestamp": int(context.timestamp),
                    "response_id": str(uuid.uuid4())[:8]
                }
                return json.dumps(response).encode('utf-8')

            # XML-style response
            elif '<' in request_text or 'xml' in request_text:
                response = '<?xml version="1.0"?><response><status>OK</status><license>valid</license></response>'
                return response.encode('utf-8')

            # Binary response for binary requests
            elif len(context.request_data) > 0 and not context.request_data.decode('utf-8', errors='ignore').isprintable():
                # Simple binary OK response
                return b'\x00\x00\x00\x01OK'

            # Default text response
            else:
                return b'LICENSE_OK'

        except Exception as e:
            self.logger.error(f"Generic response generation error: {e}")
            return b'OK'

    def get_statistics(self) -> Dict[str, Any]:
        """Get response generation statistics"""
        return self.stats.copy()

    def export_learning_data(self) -> Dict[str, Any]:
        """Export learning data for backup/analysis"""
        return {
            'learned_patterns': self.learned_patterns,
            'statistics': self.stats,
            'cache_size': len(self.response_cache)
        }

    def import_learning_data(self, data: Dict[str, Any]):
        """Import learning data from previous sessions"""
        try:
            if 'learned_patterns' in data:
                self.learned_patterns.update(data['learned_patterns'])
                self.logger.info(f"Imported learning data for {len(data['learned_patterns'])} protocols")

        except Exception as e:
            self.logger.error(f"Error importing learning data: {e}")


__all__ = ['DynamicResponseGenerator', 'ResponseContext', 'GeneratedResponse']
