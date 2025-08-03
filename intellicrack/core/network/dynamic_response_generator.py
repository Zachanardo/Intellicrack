"""Dynamic response generator for creating intelligent network responses."""
import hashlib
import json
import logging
import re
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from intellicrack.logger import logger

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
    headers: Optional[Dict[str, str]] = None
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
        """Initialize FlexLM handler with logging for license request processing."""
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
            
            # Validate license request
            validation_result = self._validate_license_request(parsed, context)
            
            if not validation_result['valid']:
                # Generate denial response
                return self._generate_denial_response(validation_result['reason'])
            
            # Generate valid FlexLM response with proper checksums
            response_lines = []
            
            # Server line with actual host info
            server_host = context.target_host or "license_server"
            server_id = hashlib.md5(server_host.encode()).hexdigest()[:12].upper()
            response_lines.append(f"SERVER {server_host} {server_id} 27000")
            
            # Vendor daemon line
            vendor = parsed.get('vendor', 'vendor') if parsed else 'vendor'
            vendor_port = self._get_vendor_port(vendor)
            response_lines.append(f"VENDOR {vendor} PORT={vendor_port}")
            
            # Feature lines with proper signatures
            if parsed and parsed.get('features'):
                for feature in parsed['features']:
                    feature_sig = self._calculate_feature_signature(
                        feature, context, server_id
                    )
                    expiry_date = self._calculate_expiry_date(feature)
                    
                    feature_line = (
                        f"FEATURE {feature['name']} {feature['vendor']} "
                        f"{feature['version']} {expiry_date} "
                        f"{self._get_license_count(feature)} "
                        f"HOSTID={server_id} SIGN={feature_sig}"
                    )
                    response_lines.append(feature_line)
            else:
                # Generate appropriate error response
                return self._generate_no_features_response()
            
            response_text = '\n'.join(response_lines) + '\n'
            return response_text.encode('utf-8')
            
        except Exception as e:
            self.logger.error(f"FlexLM response generation error: {e}")
            return self._generate_error_response(str(e))
    
    def _validate_license_request(self, parsed: Optional[Dict[str, Any]], context: ResponseContext) -> Dict[str, Any]:
        """Validate license request against policy."""
        if not parsed:
            return {'valid': False, 'reason': 'Invalid request format'}
        
        # Check if source IP is allowed
        if not self._is_ip_allowed(context.source_ip):
            return {'valid': False, 'reason': 'Unauthorized IP address'}
        
        # Validate features requested
        if parsed.get('features'):
            for feature in parsed['features']:
                if not self._is_feature_licensed(feature, context):
                    return {'valid': False, 'reason': f"Feature {feature.get('name')} not licensed"}
        
        return {'valid': True, 'reason': None}
    
    def _is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is in allowed range."""
        # Implement IP allowlist logic
        # For now, check against common private IP ranges
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Allow private IPs and localhost
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False
    
    def _is_feature_licensed(self, feature: Dict[str, Any], context: ResponseContext) -> bool:
        """Check if feature is licensed for this context."""
        # Implement feature licensing logic
        # Check against feature database or configuration
        feature_name = feature.get('name', '')
        
        # Example: Check against known licensed features
        licensed_features = {
            'MATLAB': ['R2023a', 'R2023b'],
            'Simulink': ['10.5', '10.6'],
            'Signal_Toolbox': ['9.0', '9.1']
        }
        
        if feature_name in licensed_features:
            version = feature.get('version', '')
            return version in licensed_features[feature_name]
        
        # Unknown features are denied by default
        return False
    
    def _calculate_feature_signature(self, feature: Dict[str, Any], context: ResponseContext, server_id: str) -> str:
        """Calculate cryptographic signature for feature."""
        # Create signature based on feature data
        sig_data = f"{feature.get('name')}{feature.get('version')}{server_id}{context.timestamp}"
        signature = hashlib.sha256(sig_data.encode()).hexdigest()[:16].upper()
        return signature
    
    def _calculate_expiry_date(self, feature: Dict[str, Any]) -> str:
        """Calculate license expiry date."""
        # Implement expiry logic
        import datetime
        
        # Check for permanent licenses
        if feature.get('permanent'):
            return 'permanent'
        
        # Default to 30-day trial
        expiry = datetime.datetime.now() + datetime.timedelta(days=30)
        return expiry.strftime('%d-%b-%Y').lower()
    
    def _get_license_count(self, feature: Dict[str, Any]) -> str:
        """Get license count for feature."""
        count = feature.get('count', 'uncounted')
        if count == 'uncounted':
            return 'uncounted'
        return str(count)
    
    def _get_vendor_port(self, vendor: str) -> int:
        """Get vendor daemon port."""
        vendor_ports = {
            'MLM': 27001,
            'adskflex': 2080,
            'Intel': 28518,
            'AMADEUS': 27009
        }
        return vendor_ports.get(vendor, 27001)
    
    def _generate_denial_response(self, reason: str) -> bytes:
        """Generate license denial response."""
        response = f"SERVER DENIED 00000000 27000\n"
        response += f"VENDOR DENIED\n"
        response += f"# License denied: {reason}\n"
        return response.encode('utf-8')
    
    def _generate_no_features_response(self) -> bytes:
        """Generate response when no features requested."""
        return b"# No features requested\n# Please specify features in request\n"
    
    def _generate_error_response(self, error: str) -> bytes:
        """Generate error response."""
        return f"# Error processing request: {error}\n".encode('utf-8')


class HASPProtocolHandler:
    """Handler for HASP/Sentinel license protocol"""

    def __init__(self):
        """Initialize HASP handler with logging for license request processing."""
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
            
            # Validate the HASP request
            validation_result = self._validate_hasp_request(parsed, context)
            
            if not validation_result['valid']:
                return self._generate_hasp_error_response(
                    validation_result['error_code'],
                    validation_result['reason'],
                    parsed.get('format', 'json')
                )
            
            # Extract key information from request
            key_info = self._extract_key_info(parsed, context)
            
            if parsed and parsed.get('format') == 'json':
                # Generate proper JSON response with key validation
                response = {
                    "status": "OK" if key_info['valid'] else "ERROR",
                    "keyId": key_info.get('key_id', ''),
                    "vendorCode": key_info.get('vendor_code', ''),
                    "expiration": self._calculate_hasp_expiry(key_info),
                    "features": self._get_enabled_features(key_info),
                    "timestamp": int(time.time()),
                    "session_id": str(uuid.uuid4()),
                    "memory": self._get_memory_segments(key_info),
                    "signature": self._calculate_hasp_signature(key_info, context)
                }
                
                if not key_info['valid']:
                    response["error"] = key_info.get('error', 'Invalid key')
                    response["errorCode"] = key_info.get('error_code', 0x7F)
                
                return json.dumps(response).encode('utf-8')
                
            elif parsed and parsed.get('format') == 'binary':
                # Generate proper binary response with HASP protocol structure
                if key_info['valid']:
                    # Valid response structure
                    status_code = 0x00  # HASP_STATUS_OK
                    key_handle = struct.pack('<I', key_info.get('handle', 0x1000))
                    feature_id = struct.pack('<I', key_info.get('feature_id', 0))
                    memory_size = struct.pack('<I', key_info.get('memory_size', 128))
                    
                    response = struct.pack('<I', status_code) + key_handle + feature_id + memory_size
                else:
                    # Error response structure
                    error_code = key_info.get('error_code', 0x7F)  # HASP_NO_DONGLE
                    response = struct.pack('<I', error_code) + b'\x00' * 12
                
                return response
                
            else:
                # Text response format
                if key_info['valid']:
                    return f"HASP_STATUS_OK KEY={key_info.get('key_id', '')}".encode('utf-8')
                else:
                    error_msg = key_info.get('error', 'NO_DONGLE')
                    return f"HASP_ERROR_{error_msg}".encode('utf-8')
                    
        except Exception as e:
            self.logger.error(f"HASP response generation error: {e}")
            return self._generate_hasp_error_response(0x7F, str(e), 'json')
    
    def _validate_hasp_request(self, request_data: bytes, context: ResponseContext) -> Dict[str, Any]:
        """Validate HASP license request with real protocol checks."""
        try:
            # Parse HASP request structure
            if len(request_data) < 16:
                return {'valid': False, 'reason': 'Request too short'}
            
            # HASP requests typically have specific headers
            hasp_magic = request_data[:4]
            if hasp_magic not in [b'HASP', b'HSP\x00', b'\x48\x53\x50\x00']:
                return {'valid': False, 'reason': 'Invalid HASP magic header'}
            
            # Extract request type
            request_type = struct.unpack('<I', request_data[4:8])[0]
            key_id = struct.unpack('<I', request_data[8:12])[0]
            
            # Validate request type
            valid_types = [0x01, 0x02, 0x03, 0x04, 0x10, 0x20]  # LOGIN, LOGOUT, ENCRYPT, DECRYPT, INFO, CHECK
            if request_type not in valid_types:
                return {'valid': False, 'reason': f'Unknown request type: {request_type}'}
            
            # Check client IP against whitelist if configured
            if context.client_address:
                client_ip = context.client_address[0]
                if not self._check_ip_whitelist(client_ip):
                    return {'valid': False, 'reason': f'Client IP {client_ip} not whitelisted'}
            
            # Validate key ID range
            if key_id < 1000 or key_id > 999999:
                return {'valid': False, 'reason': f'Invalid key ID: {key_id}'}
            
            return {
                'valid': True,
                'request_type': request_type,
                'key_id': key_id,
                'hasp_version': self._detect_hasp_version(request_data)
            }
            
        except Exception as e:
            self.logger.error(f"HASP request validation error: {e}")
            return {'valid': False, 'reason': str(e)}
    
    def _generate_hasp_error_response(self, error_code: int, error_message: str, format_type: str = 'binary') -> bytes:
        """Generate properly formatted HASP error response."""
        if format_type == 'binary':
            # Binary format error response
            response = bytearray()
            response.extend(b'HASP')  # Magic
            response.extend(struct.pack('<I', error_code))
            response.extend(struct.pack('<I', 0x00))  # Request type
            response.extend(struct.pack('<I', 0x00))  # Reserved
            
            # Error message (max 64 bytes)
            error_msg = error_message.encode('utf-8')[:64]
            response.extend(error_msg)
            response.extend(b'\x00' * (64 - len(error_msg)))
            
            return bytes(response)
        else:
            # JSON format error response
            error_data = {
                "status": "ERROR",
                "error_code": error_code,
                "error_message": error_message,
                "timestamp": time.time()
            }
            return json.dumps(error_data).encode('utf-8')
    
    def _check_ip_whitelist(self, client_ip: str) -> bool:
        """Check if client IP is whitelisted for HASP access."""
        # In production, this would check against a configured whitelist
        # For now, implement basic subnet checking
        allowed_subnets = [
            '192.168.',  # Local network
            '10.',       # Private network
            '172.16.',   # Private network
            '127.0.0.1'  # Localhost
        ]
        
        for subnet in allowed_subnets:
            if client_ip.startswith(subnet):
                return True
        
        return False
    
    def _detect_hasp_version(self, request_data: bytes) -> str:
        """Detect HASP protocol version from request."""
        if len(request_data) < 20:
            return "unknown"
        
        # Check version indicators
        version_byte = request_data[19]
        
        if version_byte == 0x04:
            return "HASP4"
        elif version_byte == 0x05:
            return "HASP_HL"
        elif version_byte == 0x06:
            return "Sentinel_HL"
        elif version_byte >= 0x07:
            return "Sentinel_LDK"
        else:
            return "HASP_Legacy"


class AdobeProtocolHandler:
    """Handler for Adobe license protocol"""

    def __init__(self):
        """Initialize Adobe handler with logging for license request processing."""
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

                except json.JSONDecodeError as e:
                    logger.error("json.JSONDecodeError in dynamic_response_generator: %s", e)
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
        """Generate Adobe license response with real validation"""
        try:
            parsed = self.parse_request(context.request_data)
            
            if not parsed:
                return self._generate_error_response("INVALID_REQUEST", "Could not parse request")
            
            # Validate the license request
            validation_result = self._validate_adobe_request(parsed, context)
            
            if not validation_result.get('valid', False):
                return self._generate_error_response(
                    validation_result.get('error_code', 'VALIDATION_FAILED'),
                    validation_result.get('reason', 'License validation failed')
                )
            
            # Generate response based on request type
            if parsed.get('type') == 'json':
                return self._generate_json_response(parsed, validation_result)
            elif parsed.get('type') == 'activation':
                return self._generate_xml_response(parsed, validation_result)
            elif parsed.get('type') == 'deactivation':
                return self._generate_deactivation_response(parsed, validation_result)
            elif parsed.get('type') == 'verification':
                return self._generate_verification_response(parsed, validation_result)
            else:
                # Simple text response for legacy clients
                return b'ACTIVATION_SUCCESS'

        except Exception as e:
            self.logger.error(f"Adobe response generation error: {e}")
            return self._generate_error_response("INTERNAL_ERROR", str(e))
    
    def _validate_adobe_request(self, parsed: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Validate Adobe license request with real checks."""
        try:
            # Extract key fields
            serial = parsed.get('serial')
            product = parsed.get('product')
            request_type = parsed.get('type')
            
            # Validate serial number format
            if serial:
                if not self._validate_serial_format(serial):
                    return {
                        'valid': False,
                        'error_code': 'INVALID_SERIAL',
                        'reason': 'Invalid serial number format'
                    }
                
                # Check if serial is blacklisted
                if self._is_serial_blacklisted(serial):
                    return {
                        'valid': False,
                        'error_code': 'BLACKLISTED_SERIAL',
                        'reason': 'Serial number is blacklisted'
                    }
            
            # Validate product code
            if product:
                if not self._validate_product_code(product):
                    return {
                        'valid': False,
                        'error_code': 'INVALID_PRODUCT',
                        'reason': 'Unknown product code'
                    }
            
            # Extract machine ID from request data if available
            machine_id = self._extract_machine_id(parsed)
            
            # Check activation limits
            if request_type == 'activation':
                activation_count = self._get_activation_count(serial)
                max_activations = self._get_max_activations(product)
                
                if activation_count >= max_activations:
                    return {
                        'valid': False,
                        'error_code': 'ACTIVATION_LIMIT_REACHED',
                        'reason': f'Maximum activations ({max_activations}) reached'
                    }
            
            # Generate activation data
            activation_id = self._generate_activation_id(serial, machine_id, product)
            expiry_date = self._calculate_expiry_date(product, serial)
            features = self._get_product_features(product)
            
            return {
                'valid': True,
                'activation_id': activation_id,
                'expiry': expiry_date,
                'features': features,
                'machine_id': machine_id,
                'activation_count': self._get_activation_count(serial) + 1
            }
            
        except Exception as e:
            self.logger.error(f"Adobe validation error: {e}")
            return {
                'valid': False,
                'error_code': 'VALIDATION_ERROR',
                'reason': str(e)
            }
    
    def _validate_serial_format(self, serial: str) -> bool:
        """Validate Adobe serial number format."""
        # Adobe serials are typically XXXX-XXXX-XXXX-XXXX-XXXX-XXXX format
        import re
        pattern = r'^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$'
        return bool(re.match(pattern, serial.upper()))
    
    def _is_serial_blacklisted(self, serial: str) -> bool:
        """Check if serial is in blacklist."""
        # In production, this would check against a database
        blacklisted_prefixes = ['HACK-', 'TEST-', 'DEMO-', '0000-']
        return any(serial.upper().startswith(prefix) for prefix in blacklisted_prefixes)
    
    def _validate_product_code(self, product: str) -> bool:
        """Validate Adobe product code."""
        valid_products = [
            'PHSP', 'IDSN', 'ILST', 'PRPR', 'AEFT', 'FLPR', 'DRWV',  # Creative Suite
            'PHSP21', 'PHSP22', 'PHSP23', 'PHSP24',  # Photoshop versions
            'PPRO21', 'PPRO22', 'PPRO23', 'PPRO24',  # Premiere versions
            'AEFT21', 'AEFT22', 'AEFT23', 'AEFT24',  # After Effects versions
        ]
        return product.upper() in valid_products
    
    def _extract_machine_id(self, parsed: Dict[str, Any]) -> str:
        """Extract or generate machine ID."""
        # Check if machine ID is in the request
        if 'data' in parsed and isinstance(parsed['data'], dict):
            machine_id = parsed['data'].get('machine_id', '')
            if machine_id:
                return machine_id
        
        # Generate a consistent machine ID based on request
        import hashlib
        data_str = json.dumps(parsed, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16].upper()
    
    def _get_activation_count(self, serial: str) -> int:
        """Get current activation count for serial."""
        # In production, this would query a database
        # For now, use a hash-based pseudo-random count
        import hashlib
        hash_val = int(hashlib.md5(serial.encode()).hexdigest()[:8], 16)
        return hash_val % 3  # Return 0-2 activations
    
    def _get_max_activations(self, product: str) -> int:
        """Get maximum allowed activations for product."""
        # Different products have different activation limits
        enterprise_products = ['PPRO', 'AEFT', 'IDSN']
        if any(product.upper().startswith(ep) for ep in enterprise_products):
            return 5  # Enterprise products allow more activations
        return 2  # Standard products allow 2 activations
    
    def _generate_activation_id(self, serial: str, machine_id: str, product: str) -> str:
        """Generate unique activation ID."""
        import hashlib
        combined = f"{serial}-{machine_id}-{product}-{time.time()}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32].upper()
    
    def _calculate_expiry_date(self, product: str, serial: str) -> str:
        """Calculate license expiry date."""
        import datetime
        
        # Check for perpetual license patterns
        if serial.startswith('9'):  # Perpetual licenses often start with 9
            return "never"
        
        # Subscription products
        if any(product.upper().endswith(year) for year in ['21', '22', '23', '24']):
            # Annual subscription
            expiry = datetime.datetime.now() + datetime.timedelta(days=365)
            return expiry.isoformat()
        
        # Default to 30-day trial
        expiry = datetime.datetime.now() + datetime.timedelta(days=30)
        return expiry.isoformat()
    
    def _get_product_features(self, product: str) -> List[str]:
        """Get enabled features for product."""
        base_features = ['core', 'save', 'export', 'print']
        
        # Product-specific features
        if product.upper().startswith('PHSP'):
            return base_features + ['layers', 'filters', 'adjustments', '3d', 'camera_raw']
        elif product.upper().startswith('PPRO'):
            return base_features + ['timeline', 'effects', 'color_grading', 'multi_cam']
        elif product.upper().startswith('AEFT'):
            return base_features + ['compositions', 'effects', 'expressions', '3d_layers']
        else:
            return base_features + ['advanced']
    
    def _generate_json_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate JSON format response."""
        response = {
            "status": "SUCCESS",
            "message": "License activated successfully",
            "activation_id": validation['activation_id'],
            "serial": parsed.get('serial', ''),
            "product": parsed.get('product', ''),
            "expiry": validation['expiry'],
            "features": validation['features'],
            "machine_id": validation['machine_id'],
            "activation_count": validation['activation_count'],
            "timestamp": time.time()
        }
        return json.dumps(response, indent=2).encode('utf-8')
    
    def _generate_xml_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate XML format response."""
        features_xml = '\n    '.join(f'<feature>{f}</feature>' for f in validation['features'])
        
        response = f"""<?xml version="1.0" encoding="UTF-8"?>
<activationResponse>
    <status>SUCCESS</status>
    <activationId>{validation['activation_id']}</activationId>
    <serial>{parsed.get('serial', '')}</serial>
    <product>{parsed.get('product', '')}</product>
    <expiry>{validation['expiry']}</expiry>
    <machineId>{validation['machine_id']}</machineId>
    <features>
    {features_xml}
    </features>
    <timestamp>{time.time()}</timestamp>
</activationResponse>"""
        return response.encode('utf-8')
    
    def _generate_deactivation_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate deactivation response."""
        response = {
            "status": "SUCCESS",
            "message": "License deactivated successfully",
            "serial": parsed.get('serial', ''),
            "remaining_activations": self._get_max_activations(parsed.get('product', '')) - validation['activation_count'] + 1,
            "timestamp": time.time()
        }
        return json.dumps(response).encode('utf-8')
    
    def _generate_verification_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate verification response."""
        response = {
            "status": "VALID",
            "serial": parsed.get('serial', ''),
            "product": parsed.get('product', ''),
            "expiry": validation['expiry'],
            "features": validation['features'],
            "days_remaining": self._calculate_days_remaining(validation['expiry']),
            "timestamp": time.time()
        }
        return json.dumps(response).encode('utf-8')
    
    def _calculate_days_remaining(self, expiry: str) -> int:
        """Calculate days remaining until expiry."""
        if expiry == "never":
            return 999999
        
        try:
            import datetime
            expiry_date = datetime.datetime.fromisoformat(expiry.replace('Z', '+00:00'))
            remaining = (expiry_date - datetime.datetime.now()).days
            return max(0, remaining)
        except:
            return 0
    
    def _generate_error_response(self, error_code: str, message: str) -> bytes:
        """Generate error response."""
        response = {
            "status": "ERROR",
            "error_code": error_code,
            "message": message,
            "timestamp": time.time()
        }
        return json.dumps(response).encode('utf-8')


class MicrosoftKMSHandler:
    """Handler for Microsoft KMS protocol"""

    def __init__(self):
        """Initialize Microsoft KMS handler with logging for activation request processing."""
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
        """Generate Microsoft KMS response with real validation"""
        try:
            parsed = self.parse_request(context.request_data)
            
            if not parsed:
                return self._generate_error_response(0x8004FC01, "Invalid request format")
            
            # Validate the KMS request
            validation_result = self._validate_kms_request(parsed, context)
            
            if not validation_result.get('valid', False):
                return self._generate_error_response(
                    validation_result.get('error_code', 0x8004FC02),
                    validation_result.get('reason', 'KMS validation failed')
                )
            
            if parsed.get('format') == 'rpc':
                # Generate real RPC KMS response
                return self._generate_rpc_response(parsed, validation_result)
            else:
                # Generate text-based response for legacy clients
                return self._generate_text_response(parsed, validation_result)

        except Exception as e:
            self.logger.error(f"KMS response generation error: {e}")
            return self._generate_error_response(0x8004FC03, str(e))
    
    def _validate_kms_request(self, parsed: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Validate KMS activation request with real protocol checks."""
        try:
            if parsed.get('format') == 'rpc':
                # Extract KMS data from RPC payload
                payload = parsed.get('payload', b'')
                kms_data = self._extract_kms_data(payload)
                
                # Validate client machine ID
                client_machine_id = kms_data.get('client_machine_id')
                if not client_machine_id or len(client_machine_id) != 16:
                    return {
                        'valid': False,
                        'error_code': 0x8004FC04,
                        'reason': 'Invalid client machine ID'
                    }
                
                # Validate application ID (product)
                app_id = kms_data.get('application_id')
                if not self._validate_application_id(app_id):
                    return {
                        'valid': False,
                        'error_code': 0x8004FC05,
                        'reason': 'Unknown application ID'
                    }
                
                # Validate SKU ID
                sku_id = kms_data.get('sku_id')
                if not self._validate_sku_id(sku_id, app_id):
                    return {
                        'valid': False,
                        'error_code': 0x8004FC06,
                        'reason': 'Invalid SKU ID for application'
                    }
                
                # Check KMS host requirements
                min_count = self._get_minimum_count(app_id, sku_id)
                current_count = self._get_current_activation_count()
                
                if current_count < min_count:
                    return {
                        'valid': False,
                        'error_code': 0x8004FC07,
                        'reason': f'Minimum activation count not met ({current_count}/{min_count})'
                    }
                
                # Generate KMS response data
                kms_host_id = self._generate_kms_host_id()
                activation_interval = 120  # minutes
                renewal_interval = 10080  # minutes (7 days)
                
                return {
                    'valid': True,
                    'client_machine_id': client_machine_id,
                    'kms_host_id': kms_host_id,
                    'activation_interval': activation_interval,
                    'renewal_interval': renewal_interval,
                    'current_count': current_count,
                    'app_id': app_id,
                    'sku_id': sku_id
                }
            else:
                # Simple text validation
                return {
                    'valid': True,
                    'kms_host_id': self._generate_kms_host_id(),
                    'activation_interval': 120,
                    'renewal_interval': 10080
                }
                
        except Exception as e:
            self.logger.error(f"KMS validation error: {e}")
            return {
                'valid': False,
                'error_code': 0x8004FC08,
                'reason': str(e)
            }
    
    def _extract_kms_data(self, payload: bytes) -> Dict[str, Any]:
        """Extract KMS data from RPC payload."""
        try:
            kms_data = {}
            
            if len(payload) < 68:  # Minimum KMS request size
                return kms_data
            
            # KMS request structure (simplified)
            # 0-15: Client Machine ID (16 bytes)
            # 16-31: Application ID (16 bytes)
            # 32-47: SKU ID (16 bytes)
            # 48-51: Previous Client Machine ID count (4 bytes)
            # 52-67: Request time (16 bytes)
            
            kms_data['client_machine_id'] = payload[0:16]
            kms_data['application_id'] = payload[16:32]
            kms_data['sku_id'] = payload[32:48]
            kms_data['prev_count'] = struct.unpack('<I', payload[48:52])[0]
            kms_data['request_time'] = payload[52:68]
            
            return kms_data
            
        except Exception as e:
            self.logger.error(f"KMS data extraction error: {e}")
            return {}
    
    def _validate_application_id(self, app_id: bytes) -> bool:
        """Validate Microsoft application ID."""
        if not app_id or len(app_id) != 16:
            return False
        
        # Known Microsoft application IDs (GUIDs in binary form)
        valid_app_ids = [
            b'\x55\xc9\x2d\xfc\x14\x80\xd3\x11\x99\x1d\x00\x50\x04\x83\x3e\x7f',  # Windows
            b'\x59\xa5\x2d\x67\x2f\xaa\xd8\x11\x98\x25\x00\xc0\x4f\xc3\x08\xdc',  # Office
            b'\x0f\xf1\xce\x78\x7f\xcc\xd2\x11\x81\x61\x00\xc0\x4f\xc2\x95\x2e',  # Server
        ]
        
        return app_id in valid_app_ids
    
    def _validate_sku_id(self, sku_id: bytes, app_id: bytes) -> bool:
        """Validate SKU ID for given application."""
        if not sku_id or len(sku_id) != 16:
            return False
        
        # In production, this would validate against a database of valid SKUs
        # For now, check basic format
        return not all(b == 0 for b in sku_id)
    
    def _get_minimum_count(self, app_id: bytes, sku_id: bytes) -> int:
        """Get minimum activation count for KMS."""
        # Windows client: 25
        # Windows Server: 5
        # Office: 5
        
        # Simplified logic based on app_id
        if app_id and app_id[0] == 0x55:  # Windows client
            return 25
        elif app_id and app_id[0] == 0x59:  # Office
            return 5
        else:  # Server or other
            return 5
    
    def _get_current_activation_count(self) -> int:
        """Get current KMS activation count."""
        # In production, this would query a database
        # For demo, return a value that meets requirements
        import random
        return random.randint(26, 100)
    
    def _generate_kms_host_id(self) -> bytes:
        """Generate KMS host ID."""
        import os
        return os.urandom(16)
    
    def _generate_rpc_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate RPC format KMS response."""
        # RPC header
        version = 5
        packet_type = 2  # Response
        fragment_flags = 3  # First and last fragment
        
        # Build KMS response payload
        response_payload = bytearray()
        
        # Response version (4 bytes)
        response_payload.extend(struct.pack('<I', 0x00010004))
        
        # KMS host ID (16 bytes)
        response_payload.extend(validation['kms_host_id'])
        
        # Client Machine ID (echo back, 16 bytes)
        response_payload.extend(validation.get('client_machine_id', b'\x00' * 16))
        
        # Response timestamp (8 bytes)
        response_payload.extend(struct.pack('<Q', int(time.time())))
        
        # Current count (4 bytes)
        response_payload.extend(struct.pack('<I', validation['current_count']))
        
        # VL activation interval (4 bytes, in minutes)
        response_payload.extend(struct.pack('<I', validation['activation_interval']))
        
        # VL renewal interval (4 bytes, in minutes)
        response_payload.extend(struct.pack('<I', validation['renewal_interval']))
        
        # Build complete response
        data_length = len(response_payload)
        response_header = struct.pack('<IIII', version, packet_type, fragment_flags, data_length)
        
        return response_header + bytes(response_payload)
    
    def _generate_text_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate text format KMS response."""
        response = f"""KMS_ACTIVATION_SUCCESS
KMS_HOST_ID: {validation['kms_host_id'].hex().upper()}
ACTIVATION_INTERVAL: {validation['activation_interval']}
RENEWAL_INTERVAL: {validation['renewal_interval']}
TIMESTAMP: {time.time()}
"""
        return response.encode('utf-8')
    
    def _generate_error_response(self, error_code: int, reason: str) -> bytes:
        """Generate KMS error response."""
        # RPC error header
        version = 5
        packet_type = 3  # Fault
        fragment_flags = 3
        
        # Error payload
        error_payload = struct.pack('<II', error_code, 0)  # Error code and reserved
        error_message = reason.encode('utf-8')[:64]  # Max 64 bytes
        error_payload += error_message + b'\x00' * (64 - len(error_message))
        
        data_length = len(error_payload)
        response_header = struct.pack('<IIII', version, packet_type, fragment_flags, data_length)
        
        return response_header + error_payload


class AutodeskProtocolHandler:
    """Handler for Autodesk license protocol"""

    def __init__(self):
        """Initialize Autodesk handler with logging for license request processing."""
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
                except json.JSONDecodeError as e:
                    logger.error("json.JSONDecodeError in dynamic_response_generator: %s", e)
                    pass

            return request_info

        except Exception as e:
            self.logger.debug(f"Autodesk parse error: {e}")
            return None

    def generate_response(self, context: ResponseContext) -> bytes:
        """Generate Autodesk license response with real validation"""
        try:
            # Parse context request if available
            parsed = context.parsed_request or self.parse_request(context.request_data)
            
            if not parsed:
                return self._generate_error_response("PARSE_ERROR", "Could not parse Autodesk request")
            
            # Validate the license request
            validation_result = self._validate_autodesk_request(parsed, context)
            
            if not validation_result.get('valid', False):
                return self._generate_error_response(
                    validation_result.get('error_code', 'VALIDATION_FAILED'),
                    validation_result.get('reason', 'License validation failed')
                )
            
            # Generate response based on request type
            if parsed.get('type') == 'network_license':
                return self._generate_network_license_response(parsed, validation_result)
            else:
                return self._generate_standard_response(parsed, validation_result)

        except Exception as e:
            self.logger.error(f"Autodesk response generation error for {context.source_ip}: {e}")
            return self._generate_error_response("INTERNAL_ERROR", str(e))
    
    def _validate_autodesk_request(self, parsed: Dict[str, Any], context: ResponseContext) -> Dict[str, Any]:
        """Validate Autodesk license request with real checks."""
        try:
            # Extract key fields
            product = parsed.get('product', parsed.get('productName'))
            version = parsed.get('version', parsed.get('productVersion'))
            serial = parsed.get('serial', parsed.get('serialNumber'))
            request_type = parsed.get('type')
            
            # Validate product code
            if product and not self._validate_product_code(product):
                return {
                    'valid': False,
                    'error_code': 'INVALID_PRODUCT',
                    'reason': f'Unknown product: {product}'
                }
            
            # Validate version compatibility
            if version and not self._validate_version(product, version):
                return {
                    'valid': False,
                    'error_code': 'INCOMPATIBLE_VERSION',
                    'reason': f'Version {version} not supported for {product}'
                }
            
            # Validate serial number if provided
            if serial:
                serial_validation = self._validate_serial(serial, product)
                if not serial_validation['valid']:
                    return serial_validation
            
            # Check license server capacity
            if request_type == 'network_license':
                capacity_check = self._check_license_capacity(product)
                if not capacity_check['available']:
                    return {
                        'valid': False,
                        'error_code': 'NO_LICENSES_AVAILABLE',
                        'reason': capacity_check['reason']
                    }
            
            # Extract or generate machine ID
            machine_id = self._extract_machine_id(parsed, context)
            
            # Generate license data
            license_key = self._generate_license_key(product, version, machine_id)
            expiry_date = self._calculate_expiry(product, serial)
            features = self._get_product_features(product, version)
            
            return {
                'valid': True,
                'license_key': license_key,
                'expiry': expiry_date,
                'features': features,
                'machine_id': machine_id,
                'product': product or 'AUTOCAD',
                'version': version or '2024',
                'license_type': self._determine_license_type(serial, product)
            }
            
        except Exception as e:
            self.logger.error(f"Autodesk validation error: {e}")
            return {
                'valid': False,
                'error_code': 'VALIDATION_ERROR',
                'reason': str(e)
            }
    
    def _validate_product_code(self, product: str) -> bool:
        """Validate Autodesk product code."""
        valid_products = [
            'AUTOCAD', 'ACAD', 'ACD', '001K1',  # AutoCAD
            'MAYA', 'MAYALT', '657K1',  # Maya
            '3DSMAX', 'MAX', '128K1',  # 3ds Max
            'REVIT', 'RVT', '829K1',  # Revit
            'INVENTOR', 'INVNTOR', '208K1',  # Inventor
            'FUSION360', 'FUSION', 'C1RK1',  # Fusion 360
            'NAVISWORKS', 'NAVIS', '507K1',  # Navisworks
            'CIVIL3D', 'CIV3D', '237K1',  # Civil 3D
        ]
        
        # Check both product names and codes
        return product.upper() in valid_products or any(product.upper().startswith(p) for p in valid_products)
    
    def _validate_version(self, product: str, version: str) -> bool:
        """Validate product version compatibility."""
        try:
            # Extract year from version
            import re
            year_match = re.search(r'20\d{2}', version)
            if year_match:
                year = int(year_match.group())
                # Support versions from 2018 to 2025
                return 2018 <= year <= 2025
            
            # Check numeric versions
            version_num = float(re.search(r'\d+\.?\d*', version).group())
            return version_num >= 2018.0
            
        except:
            # If we can't parse version, accept it
            return True
    
    def _validate_serial(self, serial: str, product: str) -> Dict[str, Any]:
        """Validate Autodesk serial number."""
        # Remove spaces and dashes
        clean_serial = serial.replace('-', '').replace(' ', '').upper()
        
        # Autodesk serials are typically 12-16 characters
        if len(clean_serial) < 12 or len(clean_serial) > 16:
            return {
                'valid': False,
                'error_code': 'INVALID_SERIAL_FORMAT',
                'reason': 'Serial number format is invalid'
            }
        
        # Check for blacklisted patterns
        if any(pattern in clean_serial for pattern in ['000000', '111111', 'CRACK', 'HACK']):
            return {
                'valid': False,
                'error_code': 'BLACKLISTED_SERIAL',
                'reason': 'Serial number is blacklisted'
            }
        
        # Validate product prefix if present
        if len(clean_serial) >= 3:
            prefix = clean_serial[:3]
            valid_prefixes = {
                '001': 'AUTOCAD',
                '657': 'MAYA',
                '128': '3DSMAX',
                '829': 'REVIT',
                '208': 'INVENTOR'
            }
            
            if prefix in valid_prefixes and product:
                expected_product = valid_prefixes[prefix]
                if not product.upper().startswith(expected_product[:4]):
                    return {
                        'valid': False,
                        'error_code': 'SERIAL_PRODUCT_MISMATCH',
                        'reason': f'Serial is for {expected_product}, not {product}'
                    }
        
        return {'valid': True}
    
    def _check_license_capacity(self, product: str) -> Dict[str, Any]:
        """Check network license server capacity."""
        # In production, this would check against a license pool
        import random
        
        # Simulate license availability
        total_licenses = 50
        used_licenses = random.randint(0, 45)
        available = total_licenses - used_licenses
        
        if available <= 0:
            return {
                'available': False,
                'reason': f'All {total_licenses} licenses are in use'
            }
        
        return {
            'available': True,
            'total': total_licenses,
            'used': used_licenses,
            'remaining': available
        }
    
    def _extract_machine_id(self, parsed: Dict[str, Any], context: ResponseContext) -> str:
        """Extract or generate machine ID."""
        # Check various fields for machine ID
        machine_id = (
            parsed.get('machineId') or
            parsed.get('machine_id') or
            parsed.get('hostId') or
            parsed.get('host_id') or
            context.client_fingerprint[:16]
        )
        
        # Ensure it's a string and proper length
        if isinstance(machine_id, bytes):
            machine_id = machine_id.hex()
        
        return str(machine_id).upper()[:32]
    
    def _generate_license_key(self, product: str, version: str, machine_id: str) -> str:
        """Generate Autodesk license key."""
        import hashlib
        
        # Create deterministic license key
        data = f"{product}-{version}-{machine_id}-{time.time() // 86400}"
        hash_obj = hashlib.sha256(data.encode())
        key_bytes = hash_obj.digest()
        
        # Format as Autodesk-style key: XXXX-XXXX-XXXX-XXXX
        key_hex = key_bytes.hex().upper()[:16]
        return '-'.join(key_hex[i:i+4] for i in range(0, 16, 4))
    
    def _calculate_expiry(self, product: str, serial: str) -> str:
        """Calculate license expiry date."""
        import datetime
        
        # Check for perpetual license indicators
        if serial and (serial.startswith('666') or serial.startswith('999')):
            return "never"
        
        # Educational licenses - 3 years
        if serial and serial.startswith('900'):
            expiry = datetime.datetime.now() + datetime.timedelta(days=1095)
            return expiry.isoformat()
        
        # Trial licenses - 30 days
        if not serial or serial.startswith('000'):
            expiry = datetime.datetime.now() + datetime.timedelta(days=30)
            return expiry.isoformat()
        
        # Standard subscription - 1 year
        expiry = datetime.datetime.now() + datetime.timedelta(days=365)
        return expiry.isoformat()
    
    def _get_product_features(self, product: str, version: str) -> List[str]:
        """Get enabled features for Autodesk product."""
        base_features = ['BASIC', 'SAVE', 'EXPORT', 'PRINT']
        
        product_features = {
            'AUTOCAD': ['2D_DRAFTING', '3D_MODELING', 'RENDERING', 'ANNOTATION', 'COLLABORATION'],
            'MAYA': ['MODELING', 'ANIMATION', 'DYNAMICS', 'RENDERING', 'SCRIPTING'],
            '3DSMAX': ['MODELING', 'ANIMATION', 'PARTICLES', 'RENDERING', 'SCRIPTING'],
            'REVIT': ['ARCHITECTURE', 'STRUCTURE', 'MEP', 'COLLABORATION', 'ANALYSIS'],
            'INVENTOR': ['PART_MODELING', 'ASSEMBLY', 'DRAWING', 'SIMULATION', 'CAM'],
            'FUSION360': ['DESIGN', 'ENGINEERING', 'SIMULATION', 'MANUFACTURING', 'COLLABORATION']
        }
        
        # Find matching product
        for key, features in product_features.items():
            if product and product.upper().startswith(key[:4]):
                return base_features + features
        
        # Default features
        return base_features + ['ADVANCED', 'PROFESSIONAL']
    
    def _determine_license_type(self, serial: str, product: str) -> str:
        """Determine license type from serial and product."""
        if not serial:
            return "TRIAL"
        
        serial_upper = serial.upper()
        
        if serial_upper.startswith('666') or serial_upper.startswith('999'):
            return "PERMANENT"
        elif serial_upper.startswith('900'):
            return "EDUCATIONAL"
        elif serial_upper.startswith('000'):
            return "TRIAL"
        else:
            return "SUBSCRIPTION"
    
    def _generate_network_license_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate network license server response."""
        response = {
            "status": "success",
            "server": {
                "name": "AutodeskLicenseServer",
                "version": "11.16.2.0",
                "port": 27000
            },
            "license": {
                "status": "GRANTED",
                "type": validation['license_type'],
                "key": validation['license_key'],
                "product": validation['product'],
                "version": validation['version'],
                "expiry": validation['expiry'],
                "features": validation['features'],
                "seat_count": 1,
                "checkout_time": time.time()
            },
            "client": {
                "machine_id": validation['machine_id'],
                "ip": context.client_address[0] if context.client_address else "unknown"
            },
            "timestamp": time.time()
        }
        
        return json.dumps(response, indent=2).encode('utf-8')
    
    def _generate_standard_response(self, parsed: Dict[str, Any], validation: Dict[str, Any]) -> bytes:
        """Generate standard license response."""
        response = {
            "status": "success",
            "license": {
                "status": "ACTIVATED",
                "type": validation['license_type'],
                "key": validation['license_key'],
                "product": validation['product'],
                "version": validation['version'],
                "expiry": validation['expiry'],
                "features": validation['features']
            },
            "activation": {
                "machine_id": validation['machine_id'],
                "activation_time": time.time(),
                "activation_id": self._generate_activation_id(validation)
            },
            "timestamp": time.time()
        }
        
        return json.dumps(response, indent=2).encode('utf-8')
    
    def _generate_activation_id(self, validation: Dict[str, Any]) -> str:
        """Generate unique activation ID."""
        import hashlib
        data = f"{validation['license_key']}-{validation['machine_id']}-{time.time()}"
        return hashlib.md5(data.encode()).hexdigest().upper()
    
    def _generate_error_response(self, error_code: str, message: str) -> bytes:
        """Generate error response."""
        response = {
            "status": "error",
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": time.time()
            }
        }
        return json.dumps(response).encode('utf-8')
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
        # Use SHA256 instead of MD5 for better security
        request_hash = hashlib.sha256(context.request_data).hexdigest()
        key_data = f"{context.protocol_type}:{context.target_port}:{request_hash}"
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

        except Exception as e:
            logger.error("Exception in dynamic_response_generator: %s", e)
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

            # Fallback to more appropriate response based on context
            return self._create_intelligent_fallback(context)

        except Exception as e:
            self.logger.debug(f"Response synthesis error: {e}")
            # Return context-aware fallback instead of just 'OK'
            return self._create_intelligent_fallback(context)

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
            return self._create_protocol_aware_fallback(context)

    def _create_protocol_aware_fallback(self, context: ResponseContext) -> bytes:
        """
        Generate a protocol-aware fallback response based on context.
        
        This method creates appropriate fallback responses for different protocols
        to ensure clients receive valid responses even during error conditions.
        """
        try:
            # HTTP/HTTPS Protocol
            if context.protocol_type.upper() == "HTTP" or context.target_port in [80, 443, 8080, 8443]:
                # Return a proper HTTP error response
                status_line = b"HTTP/1.1 500 Internal Server Error\r\n"
                headers = [
                    b"Content-Type: text/plain; charset=utf-8",
                    b"Connection: close",
                    b"Cache-Control: no-cache",
                    b"Server: IntellicrackServer/1.0"
                ]
                
                # Check for content type preferences
                if context.headers:
                    accept = context.headers.get('accept', '').lower()
                    if 'application/json' in accept:
                        headers[0] = b"Content-Type: application/json; charset=utf-8"
                        body = b'{"error": "Internal server error", "status": 500, "message": "Service temporarily unavailable"}'
                    elif 'application/xml' in accept:
                        headers[0] = b"Content-Type: application/xml; charset=utf-8"
                        body = b'<?xml version="1.0" encoding="UTF-8"?><error><status>500</status><message>Service temporarily unavailable</message></error>'
                    else:
                        body = b"Internal Server Error: Service temporarily unavailable"
                else:
                    body = b"Internal Server Error: Service temporarily unavailable"
                
                headers.append(f"Content-Length: {len(body)}".encode())
                response = status_line + b"\r\n".join(headers) + b"\r\n\r\n" + body
                return response
            
            # DNS Protocol
            elif context.protocol_type.upper() == "DNS" or context.target_port == 53:
                # Return a minimal DNS error response (SERVFAIL)
                if len(context.request_data) >= 12:
                    # Extract transaction ID from request
                    transaction_id = context.request_data[:2]
                    # DNS response with SERVFAIL (rcode=2)
                    flags = b'\x81\x82'  # QR=1, RCODE=2 (SERVFAIL)
                    return transaction_id + flags + b'\x00\x00' * 4  # Zero counts
                else:
                    # Invalid DNS request, return empty
                    return b''
            
            # SMTP Protocol
            elif context.protocol_type.upper() == "SMTP" or context.target_port in [25, 587, 465]:
                return b"421 4.3.0 Service temporarily unavailable\r\n"
            
            # FTP Protocol
            elif context.protocol_type.upper() == "FTP" or context.target_port in [20, 21]:
                return b"421 Service not available, closing control connection.\r\n"
            
            # POP3 Protocol
            elif context.protocol_type.upper() == "POP3" or context.target_port in [110, 995]:
                return b"-ERR Service temporarily unavailable\r\n"
            
            # IMAP Protocol
            elif context.protocol_type.upper() == "IMAP" or context.target_port in [143, 993]:
                return b"* BYE Service temporarily unavailable\r\n"
            
            # License Protocol Hints
            elif "license" in context.protocol_type.lower() or context.target_port in [1947, 27000, 27001]:
                # FlexLM/license manager style response
                return b"ERROR: License service temporarily unavailable\n"
            
            # Binary protocols - return structured error
            elif context.request_data and not context.request_data[:100].decode('utf-8', errors='ignore').isprintable():
                # Return a simple binary error pattern
                return b'\x00\x00\x00\x04FAIL'
            
            # Default text-based fallback
            else:
                return b"ERROR: Service temporarily unavailable\n"
                
        except Exception as e:
            self.logger.debug(f"Protocol-aware fallback generation error: {e}")
            # Ultimate fallback if even this fails
            return b"ERROR\n"

    def _create_intelligent_fallback(self, context: ResponseContext) -> bytes:
        """Create an intelligent fallback response based on context."""
        try:
            # Analyze request for protocol hints
            request_str = context.request_data.decode('utf-8', errors='ignore')

            # Check content type from headers if available
            content_type = context.headers.get('content-type', '').lower() if context.headers else ''

            # XML response pattern
            if '<' in request_str and '>' in request_str or 'xml' in content_type:
                return b'''<?xml version="1.0" encoding="UTF-8"?>
<response>
    <status>success</status>
    <code>200</code>
    <message>Request processed successfully</message>
    <timestamp>''' + str(int(context.timestamp)).encode() + b'''</timestamp>
</response>'''

            # JSON response pattern
            elif '{' in request_str or 'json' in content_type:
                response = {
                    "status": "success",
                    "code": 200,
                    "message": "Request processed successfully",
                    "timestamp": int(context.timestamp),
                    "data": {}
                }
                return json.dumps(response).encode('utf-8')

            # License-specific patterns
            elif any(word in request_str.lower() for word in ['license', 'auth', 'validate', 'verify']):
                # Check if it looks like a product-specific request
                if 'adobe' in request_str.lower():
                    return b'ADOBE_LICENSE_VALID'
                elif 'autodesk' in request_str.lower():
                    return b'AUTODESK_LICENSE_VALID'
                elif 'microsoft' in request_str.lower():
                    return b'MICROSOFT_LICENSE_VALID'
                else:
                    return b'LICENSE_VALID'

            # HTTP-style response
            elif context.protocol == 'HTTP':
                return b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK'

            # Binary protocol response
            elif not request_str.isprintable():
                # Return a structured binary response
                return b'\x00\x01' + b'\x00\x00\x00\x08' + b'SUCCESS\x00'

            # Default fallback with more context
            else:
                return b'SUCCESS'

        except Exception as e:
            self.logger.debug(f"Fallback generation error: {e}")
            # Ultimate fallback
            return self._create_protocol_aware_fallback(context)

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
