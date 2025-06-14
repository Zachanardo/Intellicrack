"""
Adobe Licensing Protocol Parser and Response Generator

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
import time
import hashlib
import uuid
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from ....utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class AdobeRequest:
    """Adobe licensing request structure"""
    request_type: str
    client_id: str
    machine_id: str
    product_id: str
    serial_number: str
    activation_id: str
    request_data: Dict[str, Any]
    headers: Dict[str, str]
    auth_token: str

@dataclass
class AdobeResponse:
    """Adobe licensing response structure"""
    status: str
    response_code: int
    activation_data: Dict[str, Any]
    license_data: Dict[str, Any]
    digital_signature: str
    response_headers: Dict[str, str]

class AdobeLicensingParser:
    """Real Adobe licensing protocol parser and response generator"""
    
    # Adobe request types
    ADOBE_REQUEST_TYPES = {
        "activation": "Product activation request",
        "verification": "License verification request", 
        "deactivation": "Product deactivation request",
        "heartbeat": "License heartbeat request",
        "feature_check": "Feature availability check",
        "trial_conversion": "Trial to paid conversion",
        "license_recovery": "License recovery request",
        "machine_binding": "Machine binding request",
        "subscription_check": "Subscription status check",
        "usage_report": "Usage reporting request"
    }
    
    # Adobe product IDs (common applications)
    ADOBE_PRODUCTS = {
        "PHSP": {  # Photoshop
            "name": "Adobe Photoshop",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "neural_filters", "cloud_sync", "libraries"],
            "subscription_required": True
        },
        "ILST": {  # Illustrator
            "name": "Adobe Illustrator", 
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "vector_tools", "cloud_sync", "libraries"],
            "subscription_required": True
        },
        "AEFT": {  # After Effects
            "name": "Adobe After Effects",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "3d_tools", "motion_graphics", "cloud_sync"],
            "subscription_required": True
        },
        "PPRO": {  # Premiere Pro
            "name": "Adobe Premiere Pro",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "multicam", "lumetri", "cloud_sync"],
            "subscription_required": True
        },
        "IDSN": {  # InDesign
            "name": "Adobe InDesign",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "publishing", "epub", "cloud_sync"],
            "subscription_required": True
        },
        "LTRM": {  # Lightroom
            "name": "Adobe Lightroom",
            "versions": ["Classic", "CC", "Mobile"],
            "features": ["core", "cloud_storage", "mobile_sync", "ai_tools"],
            "subscription_required": True
        },
        "DRWV": {  # Dreamweaver
            "name": "Adobe Dreamweaver",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "code_hints", "live_preview", "cloud_sync"],
            "subscription_required": True
        },
        "AUDT": {  # Audition
            "name": "Adobe Audition",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "spectral_display", "multitrack", "cloud_sync"],
            "subscription_required": True
        },
        "FLPR": {  # Animate (Flash Professional)
            "name": "Adobe Animate",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "character_animator", "html5", "cloud_sync"],
            "subscription_required": True
        },
        "KBRG": {  # Bridge
            "name": "Adobe Bridge",
            "versions": ["2024", "2023", "2022", "CC"],
            "features": ["core", "metadata", "batch_processing", "cloud_sync"],
            "subscription_required": False
        }
    }
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.active_activations = {}  # Track active activations
        self.machine_signatures = {}  # Store machine fingerprints
        self.subscription_data = {}   # Store subscription information
        self._initialize_server_keys()
        
    def _initialize_server_keys(self):
        """Initialize server cryptographic keys"""
        self.server_private_key = hashlib.sha256(b"adobe_server_private_key_2024").hexdigest()
        self.server_public_key = hashlib.sha256(b"adobe_server_public_key_2024").hexdigest()
        self.activation_seed = hashlib.md5(str(time.time()).encode()).hexdigest()
        
    def parse_request(self, http_data: str) -> Optional[AdobeRequest]:
        """
        Parse incoming Adobe licensing HTTP request
        
        Args:
            http_data: Raw HTTP request data
            
        Returns:
            Parsed AdobeRequest object or None if invalid
        """
        try:
            # Parse HTTP headers and body
            lines = http_data.split('\r\n')
            if not lines:
                return None
                
            # Parse request line
            request_line = lines[0]
            if not any(method in request_line for method in ['POST', 'GET', 'PUT']):
                return None
                
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                    
            # Parse body (usually JSON for Adobe requests)
            body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
            request_data = {}
            
            if body:
                try:
                    request_data = json.loads(body)
                except json.JSONDecodeError:
                    # Try to parse as form data
                    request_data = self._parse_form_data(body)
                    
            # Determine request type from URL path
            request_type = self._determine_request_type(request_line, headers, request_data)
            
            # Extract Adobe-specific fields
            client_id = self._extract_field(request_data, headers, ['client_id', 'clientId', 'adobeId'])
            machine_id = self._extract_field(request_data, headers, ['machine_id', 'machineId', 'deviceId'])
            product_id = self._extract_field(request_data, headers, ['product_id', 'productId', 'appId'])
            serial_number = self._extract_field(request_data, headers, ['serial_number', 'serialNumber', 'ngl_serial'])
            activation_id = self._extract_field(request_data, headers, ['activation_id', 'activationId', 'licenseId'])
            auth_token = self._extract_field(request_data, headers, ['authorization', 'auth_token', 'bearer_token'])
            
            # Remove 'Bearer ' prefix if present
            if auth_token and auth_token.startswith('Bearer '):
                auth_token = auth_token[7:]
                
            request = AdobeRequest(
                request_type=request_type,
                client_id=client_id or '',
                machine_id=machine_id or '',
                product_id=product_id or '',
                serial_number=serial_number or '',
                activation_id=activation_id or '',
                request_data=request_data,
                headers=headers,
                auth_token=auth_token or ''
            )
            
            self.logger.info(f"Parsed Adobe {request_type} request for product {product_id}")
            return request
            
        except Exception as e:
            self.logger.error(f"Failed to parse Adobe request: {e}")
            return None
            
    def _determine_request_type(self, request_line: str, headers: Dict[str, str], 
                               data: Dict[str, Any]) -> str:
        """Determine Adobe request type from URL and data"""
        request_line_lower = request_line.lower()
        
        # Check URL patterns
        if '/activate' in request_line_lower or 'activation' in request_line_lower:
            return 'activation'
        elif '/verify' in request_line_lower or 'verification' in request_line_lower:
            return 'verification'
        elif '/deactivate' in request_line_lower or 'deactivation' in request_line_lower:
            return 'deactivation'
        elif '/heartbeat' in request_line_lower or '/ping' in request_line_lower:
            return 'heartbeat'
        elif '/feature' in request_line_lower:
            return 'feature_check'
        elif '/trial' in request_line_lower:
            return 'trial_conversion'
        elif '/recovery' in request_line_lower:
            return 'license_recovery'
        elif '/bind' in request_line_lower or '/machine' in request_line_lower:
            return 'machine_binding'
        elif '/subscription' in request_line_lower:
            return 'subscription_check'
        elif '/usage' in request_line_lower or '/report' in request_line_lower:
            return 'usage_report'
            
        # Check data content
        action = data.get('action', data.get('request_type', data.get('operation', '')))
        if action:
            return action.lower()
            
        # Default to verification
        return 'verification'
        
    def _extract_field(self, data: Dict[str, Any], headers: Dict[str, str], 
                      field_names: List[str]) -> Optional[str]:
        """Extract field from request data or headers"""
        # Check data first
        for field_name in field_names:
            if field_name in data:
                return str(data[field_name])
                
        # Check headers
        for field_name in field_names:
            if field_name in headers:
                return headers[field_name]
                
        return None
        
    def _parse_form_data(self, body: str) -> Dict[str, Any]:
        """Parse form-encoded data"""
        data = {}
        try:
            pairs = body.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    data[key] = value
        except:
            pass
        return data
        
    def generate_response(self, request: AdobeRequest) -> AdobeResponse:
        """
        Generate appropriate Adobe response based on request
        
        Args:
            request: Parsed Adobe request
            
        Returns:
            Adobe response object
        """
        self.logger.info(f"Generating response for Adobe {request.request_type} request")
        
        if request.request_type == 'activation':
            return self._handle_activation(request)
        elif request.request_type == 'verification':
            return self._handle_verification(request)
        elif request.request_type == 'deactivation':
            return self._handle_deactivation(request)
        elif request.request_type == 'heartbeat':
            return self._handle_heartbeat(request)
        elif request.request_type == 'feature_check':
            return self._handle_feature_check(request)
        elif request.request_type == 'trial_conversion':
            return self._handle_trial_conversion(request)
        elif request.request_type == 'license_recovery':
            return self._handle_license_recovery(request)
        elif request.request_type == 'machine_binding':
            return self._handle_machine_binding(request)
        elif request.request_type == 'subscription_check':
            return self._handle_subscription_check(request)
        elif request.request_type == 'usage_report':
            return self._handle_usage_report(request)
        else:
            return self._handle_unknown_request(request)
            
    def _handle_activation(self, request: AdobeRequest) -> AdobeResponse:
        """Handle Adobe product activation"""
        product_id = request.product_id or 'UNKNOWN'
        
        # Validate product
        if product_id not in self.ADOBE_PRODUCTS:
            return AdobeResponse(
                status="error",
                response_code=404,
                activation_data={},
                license_data={"error": f"Unknown product: {product_id}"},
                digital_signature="",
                response_headers={"Content-Type": "application/json"}
            )
            
        product = self.ADOBE_PRODUCTS[product_id]
        
        # Generate activation ID if not provided
        if not request.activation_id:
            activation_id = str(uuid.uuid4()).upper()
        else:
            activation_id = request.activation_id
            
        # Generate machine signature
        machine_signature = self._generate_machine_signature(request)
        
        # Store activation
        self.active_activations[activation_id] = {
            "product_id": product_id,
            "client_id": request.client_id,
            "machine_id": request.machine_id,
            "serial_number": request.serial_number,
            "activation_time": time.time(),
            "machine_signature": machine_signature,
            "features_enabled": product["features"]
        }
        
        # Generate license data
        license_data = {
            "activation_id": activation_id,
            "product_name": product["name"],
            "license_type": "subscription" if product["subscription_required"] else "perpetual",
            "features": product["features"],
            "expiry_date": self._calculate_expiry_date(product),
            "max_activations": 2,
            "current_activations": 1,
            "license_server": "intellicrack-adobe",
            "activation_count": 1
        }
        
        # Generate digital signature
        signature_data = f"{activation_id}:{product_id}:{request.machine_id}:{time.time()}"
        digital_signature = hashlib.sha256(
            (signature_data + self.server_private_key).encode()
        ).hexdigest()
        
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={
                "activation_id": activation_id,
                "activation_status": "activated",
                "activation_time": int(time.time()),
                "machine_signature": machine_signature
            },
            license_data=license_data,
            digital_signature=digital_signature,
            response_headers={
                "Content-Type": "application/json",
                "X-Adobe-License-Server": "intellicrack-adobe-emulator"
            }
        )
        
    def _handle_verification(self, request: AdobeRequest) -> AdobeResponse:
        """Handle license verification"""
        activation_id = request.activation_id
        
        if activation_id and activation_id in self.active_activations:
            activation = self.active_activations[activation_id]
            
            # Verify machine signature
            expected_signature = activation["machine_signature"]
            current_signature = self._generate_machine_signature(request)
            
            if current_signature != expected_signature:
                return AdobeResponse(
                    status="error",
                    response_code=403,
                    activation_data={},
                    license_data={"error": "Machine signature mismatch"},
                    digital_signature="",
                    response_headers={"Content-Type": "application/json"}
                )
                
            # Update last verification time
            activation["last_verification"] = time.time()
            
            return AdobeResponse(
                status="success",
                response_code=200,
                activation_data={
                    "verification_status": "valid",
                    "verification_time": int(time.time())
                },
                license_data={
                    "license_valid": True,
                    "days_remaining": 365,
                    "features_enabled": activation["features_enabled"]
                },
                digital_signature=self._generate_verification_signature(request),
                response_headers={"Content-Type": "application/json"}
            )
        else:
            # Allow verification to succeed for unknown activations
            return AdobeResponse(
                status="success", 
                response_code=200,
                activation_data={
                    "verification_status": "valid",
                    "verification_time": int(time.time())
                },
                license_data={
                    "license_valid": True,
                    "days_remaining": 365,
                    "features_enabled": ["core", "premium", "cloud_sync"]
                },
                digital_signature=self._generate_verification_signature(request),
                response_headers={"Content-Type": "application/json"}
            )
            
    def _handle_deactivation(self, request: AdobeRequest) -> AdobeResponse:
        """Handle product deactivation"""
        activation_id = request.activation_id
        
        if activation_id in self.active_activations:
            del self.active_activations[activation_id]
            
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={
                "deactivation_status": "deactivated",
                "deactivation_time": int(time.time())
            },
            license_data={},
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_heartbeat(self, request: AdobeRequest) -> AdobeResponse:
        """Handle license heartbeat"""
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={
                "heartbeat_status": "alive",
                "server_time": int(time.time())
            },
            license_data={
                "license_server_status": "online",
                "next_heartbeat": int(time.time() + 3600)  # 1 hour
            },
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_feature_check(self, request: AdobeRequest) -> AdobeResponse:
        """Handle feature availability check"""
        product_id = request.product_id or 'UNKNOWN'
        
        if product_id in self.ADOBE_PRODUCTS:
            features = self.ADOBE_PRODUCTS[product_id]["features"]
        else:
            features = ["core", "premium"]  # Default features
            
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={},
            license_data={
                "features_available": features,
                "features_enabled": features,  # Enable all features
                "feature_restrictions": {}
            },
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_trial_conversion(self, request: AdobeRequest) -> AdobeResponse:
        """Handle trial to paid conversion"""
        return AdobeResponse(
            status="success", 
            response_code=200,
            activation_data={
                "conversion_status": "converted",
                "conversion_time": int(time.time())
            },
            license_data={
                "license_type": "subscription",
                "trial_status": "converted",
                "subscription_active": True,
                "days_remaining": 365
            },
            digital_signature=self._generate_verification_signature(request),
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_license_recovery(self, request: AdobeRequest) -> AdobeResponse:
        """Handle license recovery"""
        # Generate new activation for recovery
        activation_id = str(uuid.uuid4()).upper()
        
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={
                "recovery_status": "recovered",
                "new_activation_id": activation_id
            },
            license_data={
                "license_recovered": True,
                "activation_id": activation_id,
                "recovery_time": int(time.time())
            },
            digital_signature=self._generate_verification_signature(request),
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_machine_binding(self, request: AdobeRequest) -> AdobeResponse:
        """Handle machine binding request"""
        machine_signature = self._generate_machine_signature(request)
        
        return AdobeResponse(
            status="success",
            response_code=200, 
            activation_data={
                "binding_status": "bound",
                "machine_signature": machine_signature
            },
            license_data={
                "machine_bound": True,
                "binding_time": int(time.time())
            },
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_subscription_check(self, request: AdobeRequest) -> AdobeResponse:
        """Handle subscription status check"""
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={},
            license_data={
                "subscription_active": True,
                "subscription_type": "individual",
                "next_billing_date": int(time.time() + 2592000),  # 30 days
                "auto_renew": True,
                "payment_method": "credit_card",
                "subscription_id": str(uuid.uuid4()).upper()
            },
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_usage_report(self, request: AdobeRequest) -> AdobeResponse:
        """Handle usage reporting"""
        return AdobeResponse(
            status="success",
            response_code=200,
            activation_data={
                "report_received": True,
                "report_time": int(time.time())
            },
            license_data={},
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _handle_unknown_request(self, request: AdobeRequest) -> AdobeResponse:
        """Handle unknown request type"""
        self.logger.warning(f"Unknown Adobe request type: {request.request_type}")
        return AdobeResponse(
            status="error",
            response_code=400,
            activation_data={},
            license_data={"error": f"Unknown request type: {request.request_type}"},
            digital_signature="",
            response_headers={"Content-Type": "application/json"}
        )
        
    def _generate_machine_signature(self, request: AdobeRequest) -> str:
        """Generate machine signature from request data"""
        signature_data = f"{request.machine_id}:{request.client_id}:{request.product_id}"
        return hashlib.md5(signature_data.encode()).hexdigest().upper()
        
    def _generate_verification_signature(self, request: AdobeRequest) -> str:
        """Generate verification signature"""
        verification_data = f"{request.activation_id}:{request.machine_id}:{time.time()}"
        return hashlib.sha256(
            (verification_data + self.server_private_key).encode()
        ).hexdigest()
        
    def _calculate_expiry_date(self, product: Dict[str, Any]) -> str:
        """Calculate license expiry date"""
        if product["subscription_required"]:
            # Subscription licenses expire in 1 year
            expiry_time = time.time() + (365 * 24 * 3600)
            return time.strftime("%Y-%m-%d", time.localtime(expiry_time))
        else:
            # Perpetual licenses don't expire
            return "permanent"
            
    def serialize_response(self, response: AdobeResponse) -> str:
        """
        Serialize Adobe response to HTTP response
        
        Args:
            response: Adobe response object
            
        Returns:
            HTTP response string
        """
        try:
            # Prepare response body
            response_body = {
                "status": response.status,
                "activation_data": response.activation_data,
                "license_data": response.license_data
            }
            
            if response.digital_signature:
                response_body["signature"] = response.digital_signature
                
            body_json = json.dumps(response_body, indent=2)
            
            # Build HTTP response
            http_response = f"HTTP/1.1 {response.response_code} OK\r\n"
            
            # Add headers
            for header_name, header_value in response.response_headers.items():
                http_response += f"{header_name}: {header_value}\r\n"
                
            # Add standard headers
            http_response += f"Content-Length: {len(body_json)}\r\n"
            http_response += "Server: intellicrack-adobe-emulator\r\n"
            http_response += f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
            http_response += "Connection: close\r\n"
            http_response += "\r\n"
            http_response += body_json
            
            return http_response
            
        except Exception as e:
            self.logger.error(f"Failed to serialize Adobe response: {e}")
            # Return minimal error response
            error_body = '{"status": "error", "message": "Internal server error"}'
            return (f"HTTP/1.1 500 Internal Server Error\r\n"
                   f"Content-Type: application/json\r\n"
                   f"Content-Length: {len(error_body)}\r\n"
                   f"\r\n{error_body}")