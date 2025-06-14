"""
Dynamic Response Generation Engine

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
import random
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from ..utils.logger import get_logger

# Import protocol parsers for response generation
try:
    from .protocols.flexlm_parser import FlexLMProtocolParser, FlexLMRequest
    from .protocols.hasp_parser import HASPSentinelParser, HASPRequest
    from .protocols.codemeter_parser import CodeMeterProtocolParser, CodeMeterRequest
    from .protocols.adobe_parser import AdobeLicensingParser, AdobeRequest
    from .protocols.autodesk_parser import AutodeskLicensingParser, AutodeskRequest
    HAS_PROTOCOL_PARSERS = True
except ImportError:
    HAS_PROTOCOL_PARSERS = False

logger = get_logger(__name__)

@dataclass
class ResponseContext:
    """Context information for response generation"""
    source_ip: str
    source_port: int
    target_host: str
    target_port: int
    protocol_type: str
    request_data: bytes
    parsed_request: Optional[Any]
    client_fingerprint: str
    timestamp: float

@dataclass
class GeneratedResponse:
    """Generated license response"""
    response_data: bytes
    response_type: str
    confidence: float
    protocol_used: str
    generation_method: str
    metadata: Dict[str, Any]

class DynamicResponseGenerator:
    """Generates dynamic license responses based on request content and context"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.protocol_parsers = {}
        self.response_templates = {}
        self.client_profiles = {}  # Track client behavior patterns
        self.response_cache = {}   # Cache responses for consistency
        self.learning_data = []    # Collect data for learning patterns
        
        # Initialize protocol parsers
        self._initialize_parsers()
        
        # Load response templates
        self._load_response_templates()
        
        # Initialize response strategies
        self._initialize_strategies()
        
    def _initialize_parsers(self):
        """Initialize protocol parsers for response generation"""
        if not HAS_PROTOCOL_PARSERS:
            self.logger.warning("Protocol parsers not available")
            return
            
        try:
            self.protocol_parsers = {
                "flexlm": FlexLMProtocolParser(),
                "hasp": HASPSentinelParser(),
                "codemeter": CodeMeterProtocolParser(),
                "adobe": AdobeLicensingParser(),
                "autodesk": AutodeskLicensingParser()
            }
            self.logger.info(f"Initialized {len(self.protocol_parsers)} response generators")
        except Exception as e:
            self.logger.error(f"Failed to initialize parsers: {e}")
            
    def _load_response_templates(self):
        """Load response templates for different scenarios"""
        self.response_templates = {
            "http_success": {
                "status_code": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Server": "intellicrack-license-server"
                },
                "body": {
                    "status": "success",
                    "license_valid": True,
                    "expiry_date": "2025-12-31"
                }
            },
            "http_activation": {
                "status_code": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "X-License-Server": "intellicrack"
                },
                "body": {
                    "activation_id": None,  # Will be generated
                    "status": "activated",
                    "license_key": None,    # Will be generated
                    "expiry_date": "2025-12-31"
                }
            },
            "binary_success": {
                "status": b'\x00\x00\x00\x00',  # Generic success
                "data": b'\x01\x00\x00\x00'     # Success flag
            },
            "flexlm_checkout": {
                "magic": b'FLEX',
                "status": 0x00,  # SUCCESS
                "feature_granted": True
            }
        }
        
    def _initialize_strategies(self):
        """Initialize response generation strategies"""
        self.strategies = {
            "adaptive": self._adaptive_response_strategy,
            "permissive": self._permissive_response_strategy,
            "authentic": self._authentic_response_strategy,
            "learning": self._learning_response_strategy
        }
        
        self.default_strategy = "adaptive"
        
    def generate_response(self, context: ResponseContext, 
                         strategy: str = None) -> GeneratedResponse:
        """
        Generate dynamic response based on request context
        
        Args:
            context: Request context information
            strategy: Response generation strategy to use
            
        Returns:
            Generated response object
        """
        if strategy is None:
            strategy = self.default_strategy
            
        self.logger.info(f"Generating {strategy} response for {context.protocol_type}")
        
        try:
            # Update client profile
            self._update_client_profile(context)
            
            # Check response cache first
            cache_key = self._get_cache_key(context)
            if cache_key in self.response_cache:
                cached_response = self.response_cache[cache_key]
                self.logger.debug(f"Using cached response for {context.protocol_type}")
                return cached_response
                
            # Generate response using selected strategy
            if strategy in self.strategies:
                response = self.strategies[strategy](context)
            else:
                self.logger.warning(f"Unknown strategy {strategy}, using default")
                response = self.strategies[self.default_strategy](context)
                
            # Cache the response
            self.response_cache[cache_key] = response
            
            # Add to learning data
            self._add_learning_data(context, response)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Failed to generate response: {e}")
            return self._generate_fallback_response(context)
            
    def _adaptive_response_strategy(self, context: ResponseContext) -> GeneratedResponse:
        """Adaptive strategy that learns from request patterns"""
        try:
            # First try protocol-specific parsing and response
            if context.protocol_type in self.protocol_parsers:
                parser = self.protocol_parsers[context.protocol_type]
                
                # Parse the request
                if hasattr(parser, 'parse_request'):
                    try:
                        parsed_request = parser.parse_request(context.request_data)
                        if parsed_request:
                            # Generate response using parser
                            response_obj = parser.generate_response(parsed_request)
                            response_data = parser.serialize_response(response_obj)
                            
                            return GeneratedResponse(
                                response_data=response_data,
                                response_type="protocol_specific",
                                confidence=0.9,
                                protocol_used=context.protocol_type,
                                generation_method="adaptive_parsed",
                                metadata={
                                    "parsed_request": str(type(parsed_request).__name__),
                                    "response_size": len(response_data)
                                }
                            )
                    except Exception as e:
                        self.logger.debug(f"Protocol parsing failed: {e}")
                        
            # Fall back to pattern-based response
            return self._pattern_based_response(context)
            
        except Exception as e:
            self.logger.error(f"Adaptive strategy failed: {e}")
            return self._generate_fallback_response(context)
            
    def _permissive_response_strategy(self, context: ResponseContext) -> GeneratedResponse:
        """Permissive strategy that always grants access"""
        try:
            # Detect request type and generate permissive response
            if self._is_http_request(context.request_data):
                return self._generate_http_success_response(context)
            elif context.protocol_type == "flexlm":
                return self._generate_flexlm_success_response(context)
            elif context.protocol_type == "hasp":
                return self._generate_hasp_success_response(context)
            elif context.protocol_type == "codemeter":
                return self._generate_codemeter_success_response(context)
            else:
                return self._generate_binary_success_response(context)
                
        except Exception as e:
            self.logger.error(f"Permissive strategy failed: {e}")
            return self._generate_fallback_response(context)
            
    def _authentic_response_strategy(self, context: ResponseContext) -> GeneratedResponse:
        """Authentic strategy that mimics real server responses"""
        try:
            # Analyze request to determine authentic response format
            request_analysis = self._analyze_request_format(context)
            
            # Generate response that matches expected format
            if request_analysis["is_http"]:
                return self._generate_authentic_http_response(context, request_analysis)
            else:
                return self._generate_authentic_binary_response(context, request_analysis)
                
        except Exception as e:
            self.logger.error(f"Authentic strategy failed: {e}")
            return self._generate_fallback_response(context)
            
    def _learning_response_strategy(self, context: ResponseContext) -> GeneratedResponse:
        """Learning strategy that improves based on past interactions"""
        try:
            # Check if we have learned patterns for this client
            client_profile = self.client_profiles.get(context.client_fingerprint, {})
            
            if client_profile.get("learned_patterns"):
                # Use learned patterns to generate response
                return self._generate_learned_response(context, client_profile)
            else:
                # Fall back to adaptive strategy while learning
                return self._adaptive_response_strategy(context)
                
        except Exception as e:
            self.logger.error(f"Learning strategy failed: {e}")
            return self._generate_fallback_response(context)
            
    def _pattern_based_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate response based on request patterns"""
        try:
            # Analyze request patterns
            patterns = self._extract_request_patterns(context.request_data)
            
            # Generate response based on patterns
            if patterns.get("has_json"):
                return self._generate_json_response(context, patterns)
            elif patterns.get("has_xml"):
                return self._generate_xml_response(context, patterns)
            elif patterns.get("has_binary_header"):
                return self._generate_binary_response(context, patterns)
            else:
                return self._generate_generic_response(context)
                
        except Exception as e:
            self.logger.error(f"Pattern-based response failed: {e}")
            return self._generate_fallback_response(context)
            
    def _is_http_request(self, data: bytes) -> bool:
        """Check if request appears to be HTTP"""
        try:
            text = data[:100].decode('utf-8', errors='ignore')
            return any(method in text for method in ['GET ', 'POST ', 'PUT ', 'DELETE '])
        except:
            return False
            
    def _generate_http_success_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate HTTP success response"""
        try:
            # Parse HTTP request to extract details
            request_details = self._parse_http_request(context.request_data)
            
            # Generate appropriate response body
            response_body = {
                "status": "success",
                "timestamp": int(time.time()),
                "license_valid": True,
                "expiry_date": "2025-12-31",
                "features_enabled": ["full_access"],
                "server_info": {
                    "name": "intellicrack-license-server",
                    "version": "1.0.0"
                }
            }
            
            # Add request-specific fields
            if request_details.get("product_id"):
                response_body["product_id"] = request_details["product_id"]
            if request_details.get("user_id"):
                response_body["user_id"] = request_details["user_id"]
                
            body_json = json.dumps(response_body, indent=2)
            
            # Build HTTP response
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_json)}\r\n"
                f"Server: intellicrack-license-server\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body_json}"
            )
            
            return GeneratedResponse(
                response_data=http_response.encode(),
                response_type="http_success",
                confidence=0.8,
                protocol_used="http",
                generation_method="permissive_http",
                metadata={
                    "status_code": 200,
                    "content_type": "application/json",
                    "body_size": len(body_json)
                }
            )
            
        except Exception as e:
            self.logger.error(f"HTTP response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _generate_flexlm_success_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate FlexLM success response"""
        try:
            import struct
            
            # Basic FlexLM response structure
            response = bytearray()
            
            # Magic number
            response.extend(struct.pack('>I', 0x464C4558))  # "FLEX"
            
            # Status (success)
            response.extend(struct.pack('>H', 0x00))
            
            # Sequence number (echo from request if possible)
            sequence = 1
            try:
                if len(context.request_data) >= 12:
                    sequence = struct.unpack('>I', context.request_data[8:12])[0]
            except:
                pass
            response.extend(struct.pack('>I', sequence))
            
            # Server version
            server_version = "11.18.0\x00"
            response.extend(server_version.encode())
            
            # Feature name (extract from request or use default)
            feature_name = "GRANTED_FEATURE\x00"
            response.extend(feature_name.encode())
            
            # Expiry date
            expiry_date = "31-dec-2025\x00"
            response.extend(expiry_date.encode())
            
            # License key
            license_key = hashlib.md5(f"{context.source_ip}:{time.time()}".encode()).hexdigest()[:16]
            response.extend(f"{license_key}\x00".encode())
            
            return GeneratedResponse(
                response_data=bytes(response),
                response_type="flexlm_success",
                confidence=0.8,
                protocol_used="flexlm",
                generation_method="permissive_binary",
                metadata={
                    "sequence": sequence,
                    "license_key": license_key
                }
            )
            
        except Exception as e:
            self.logger.error(f"FlexLM response generation failed: {e}")
            return self._generate_fallback_response(context)            
    def _generate_hasp_success_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate HASP/Sentinel success response"""
        try:
            import struct
            
            response = bytearray()
            
            # Magic signature
            response.extend(struct.pack('<I', 0x48415350))  # "HASP"
            
            # Status (success)
            response.extend(struct.pack('<I', 0x00000000))
            
            # Session ID
            session_id = random.randint(1000, 9999)
            response.extend(struct.pack('<I', session_id))
            
            # Feature ID (extract from request or default)
            feature_id = 999
            response.extend(struct.pack('<I', feature_id))
            
            # License data as JSON
            license_data = {
                "status": "ok",
                "features_granted": 0xFFFFFFFF,
                "expiry_date": "31-dec-2025"
            }
            license_json = json.dumps(license_data).encode('utf-8')
            response.extend(struct.pack('<H', len(license_json)))
            response.extend(license_json)
            
            # Empty encryption response
            response.extend(struct.pack('<H', 0))
            
            # Expiry info
            expiry_info = {"days_remaining": 365}
            expiry_json = json.dumps(expiry_info).encode('utf-8')
            response.extend(struct.pack('<H', len(expiry_json)))
            response.extend(expiry_json)
            
            # Hardware info
            hardware_info = {
                "hasp_id": 123456,
                "type": "HASP HL Max",
                "memory": 65536
            }
            hardware_json = json.dumps(hardware_info).encode('utf-8')
            response.extend(struct.pack('<H', len(hardware_json)))
            response.extend(hardware_json)
            
            return GeneratedResponse(
                response_data=bytes(response),
                response_type="hasp_success",
                confidence=0.8,
                protocol_used="hasp",
                generation_method="permissive_binary",
                metadata={
                    "session_id": session_id,
                    "feature_id": feature_id
                }
            )
            
        except Exception as e:
            self.logger.error(f"HASP response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _generate_codemeter_success_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate CodeMeter success response"""
        try:
            import struct
            
            response = bytearray()
            
            # Magic signature
            response.extend(struct.pack('<I', 0x434D4554))  # "CMET"
            
            # Status (success)
            response.extend(struct.pack('<I', 0x00000000))
            
            # Request ID (echo from request)
            request_id = random.randint(1, 65535)
            response.extend(struct.pack('<I', request_id))
            
            # Firm code
            firm_code = 500001
            response.extend(struct.pack('<I', firm_code))
            
            # Product code
            product_code = 1
            response.extend(struct.pack('<I', product_code))
            
            # License info
            license_info = {
                "name": "GRANTED_PRODUCT",
                "features": 0xFFFFFFFF,
                "max_users": 999,
                "expiry": "31-dec-2025"
            }
            license_data = self._serialize_dict(license_info)
            response.extend(struct.pack('<H', len(license_data)))
            response.extend(license_data)
            
            # Response data (success indicator)
            response_data = b'\x01\x00\x00\x00'
            response.extend(struct.pack('<H', len(response_data)))
            response.extend(response_data)
            
            # Container info
            container_info = {
                "serial_number": 1234567,
                "type": "CmStick/T",
                "memory_total": 65536
            }
            container_data = self._serialize_dict(container_info)
            response.extend(struct.pack('<H', len(container_data)))
            response.extend(container_data)
            
            # Expiry data
            expiry_data = {"license_type": "permanent"}
            expiry_serialized = self._serialize_dict(expiry_data)
            response.extend(struct.pack('<H', len(expiry_serialized)))
            response.extend(expiry_serialized)
            
            return GeneratedResponse(
                response_data=bytes(response),
                response_type="codemeter_success",
                confidence=0.8,
                protocol_used="codemeter",
                generation_method="permissive_binary",
                metadata={
                    "firm_code": firm_code,
                    "product_code": product_code
                }
            )
            
        except Exception as e:
            self.logger.error(f"CodeMeter response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _generate_binary_success_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate generic binary success response"""
        try:
            # Simple success response
            response_data = b'\x00\x00\x00\x00\x01\x00\x00\x00'  # Status OK + Success flag
            
            return GeneratedResponse(
                response_data=response_data,
                response_type="binary_success",
                confidence=0.6,
                protocol_used="generic",
                generation_method="permissive_binary",
                metadata={
                    "response_size": len(response_data)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Binary response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _analyze_request_format(self, context: ResponseContext) -> Dict[str, Any]:
        """Analyze request format for authentic response generation"""
        analysis = {
            "is_http": False,
            "is_json": False,
            "is_xml": False,
            "has_headers": False,
            "encoding": "binary",
            "patterns": []
        }
        
        try:
            # Check if HTTP
            if self._is_http_request(context.request_data):
                analysis["is_http"] = True
                analysis["has_headers"] = True
                analysis["encoding"] = "text"
                
                # Parse HTTP request for more details
                request_text = context.request_data.decode('utf-8', errors='ignore')
                
                if 'application/json' in request_text.lower():
                    analysis["is_json"] = True
                elif 'application/xml' in request_text.lower() or 'text/xml' in request_text.lower():
                    analysis["is_xml"] = True
                    
                # Extract patterns
                if 'authorization:' in request_text.lower():
                    analysis["patterns"].append("has_auth")
                if 'product' in request_text.lower():
                    analysis["patterns"].append("has_product_info")
                if 'license' in request_text.lower():
                    analysis["patterns"].append("has_license_info")
                    
            else:
                # Binary analysis
                data = context.request_data
                
                # Check for common binary patterns
                if len(data) >= 4:
                    header = data[:4]
                    if header in [b'FLEX', b'HASP', b'CMET']:
                        analysis["patterns"].append(f"header_{header.decode()}")
                        
                # Check for structured data
                if b'{' in data and b'}' in data:
                    analysis["is_json"] = True
                if b'<' in data and b'>' in data:
                    analysis["is_xml"] = True
                    
        except Exception as e:
            self.logger.debug(f"Request analysis failed: {e}")
            
        return analysis
        
    def _generate_authentic_http_response(self, context: ResponseContext, 
                                        analysis: Dict[str, Any]) -> GeneratedResponse:
        """Generate authentic HTTP response"""
        try:
            # Extract request details
            request_details = self._parse_http_request(context.request_data)
            
            # Generate response that matches request style
            if analysis["is_json"]:
                response_body = self._generate_json_response_body(request_details, analysis)
                content_type = "application/json"
            elif analysis["is_xml"]:
                response_body = self._generate_xml_response_body(request_details, analysis)
                content_type = "application/xml"
            else:
                response_body = "OK"
                content_type = "text/plain"
                
            # Build authentic HTTP response
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                f"Server: {self._get_authentic_server_name(context)}\r\n"
                f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{response_body}"
            )
            
            return GeneratedResponse(
                response_data=http_response.encode(),
                response_type="authentic_http",
                confidence=0.9,
                protocol_used="http",
                generation_method="authentic",
                metadata={
                    "content_type": content_type,
                    "server_name": self._get_authentic_server_name(context)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Authentic HTTP response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _generate_authentic_binary_response(self, context: ResponseContext,
                                          analysis: Dict[str, Any]) -> GeneratedResponse:
        """Generate authentic binary response"""
        try:
            # Match binary format based on patterns
            if "header_FLEX" in analysis["patterns"]:
                return self._generate_flexlm_success_response(context)
            elif "header_HASP" in analysis["patterns"]:
                return self._generate_hasp_success_response(context)
            elif "header_CMET" in analysis["patterns"]:
                return self._generate_codemeter_success_response(context)
            else:
                # Generate generic but authentic-looking binary response
                import struct
                response = struct.pack('<II', 0x00000000, int(time.time()))  # Status + timestamp
                
                return GeneratedResponse(
                    response_data=response,
                    response_type="authentic_binary",
                    confidence=0.7,
                    protocol_used="generic",
                    generation_method="authentic",
                    metadata={"timestamp": int(time.time())}
                )
                
        except Exception as e:
            self.logger.error(f"Authentic binary response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def _update_client_profile(self, context: ResponseContext):
        """Update client behavior profile"""
        try:
            if context.client_fingerprint not in self.client_profiles:
                self.client_profiles[context.client_fingerprint] = {
                    "first_seen": time.time(),
                    "request_count": 0,
                    "protocols_used": set(),
                    "request_patterns": [],
                    "learned_patterns": {}
                }
                
            profile = self.client_profiles[context.client_fingerprint]
            profile["request_count"] += 1
            profile["protocols_used"].add(context.protocol_type)
            profile["last_seen"] = time.time()
            
            # Extract request patterns
            patterns = self._extract_request_patterns(context.request_data)
            profile["request_patterns"].append(patterns)
            
            # Keep only recent patterns (last 10)
            if len(profile["request_patterns"]) > 10:
                profile["request_patterns"] = profile["request_patterns"][-10:]
                
        except Exception as e:
            self.logger.debug(f"Failed to update client profile: {e}")
            
    def _get_cache_key(self, context: ResponseContext) -> str:
        """Generate cache key for response"""
        try:
            key_data = f"{context.protocol_type}:{context.target_port}:{hashlib.md5(context.request_data).hexdigest()[:8]}"
            return hashlib.md5(key_data.encode()).hexdigest()
        except:
            return str(time.time())
            
    def _add_learning_data(self, context: ResponseContext, response: GeneratedResponse):
        """Add interaction to learning data"""
        try:
            learning_entry = {
                "timestamp": context.timestamp,
                "protocol_type": context.protocol_type,
                "client_fingerprint": context.client_fingerprint,
                "request_size": len(context.request_data),
                "response_type": response.response_type,
                "confidence": response.confidence,
                "generation_method": response.generation_method
            }
            
            self.learning_data.append(learning_entry)
            
            # Keep only recent learning data (last 1000 entries)
            if len(self.learning_data) > 1000:
                self.learning_data = self.learning_data[-1000:]
                
        except Exception as e:
            self.logger.debug(f"Failed to add learning data: {e}")
            
    def _generate_fallback_response(self, context: ResponseContext) -> GeneratedResponse:
        """Generate fallback response when all else fails"""
        try:
            if self._is_http_request(context.request_data):
                # HTTP fallback
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 2\r\n"
                    "\r\n"
                    "OK"
                )
                return GeneratedResponse(
                    response_data=response.encode(),
                    response_type="fallback_http",
                    confidence=0.3,
                    protocol_used="http",
                    generation_method="fallback",
                    metadata={}
                )
            else:
                # Binary fallback
                return GeneratedResponse(
                    response_data=b'\x00\x00\x00\x00',
                    response_type="fallback_binary",
                    confidence=0.3,
                    protocol_used="generic",
                    generation_method="fallback",
                    metadata={}
                )
                
        except Exception as e:
            self.logger.error(f"Even fallback response failed: {e}")
            return GeneratedResponse(
                response_data=b'\x00',
                response_type="emergency",
                confidence=0.1,
                protocol_used="unknown",
                generation_method="emergency",
                metadata={}
            )            
    def _extract_request_patterns(self, data: bytes) -> Dict[str, Any]:
        """Extract patterns from request data"""
        patterns = {
            "has_json": False,
            "has_xml": False,
            "has_binary_header": False,
            "has_timestamps": False,
            "has_ids": False,
            "size_category": "small"
        }
        
        try:
            # Size categorization
            if len(data) < 256:
                patterns["size_category"] = "small"
            elif len(data) < 1024:
                patterns["size_category"] = "medium"
            else:
                patterns["size_category"] = "large"
                
            # Content analysis
            text = data.decode('utf-8', errors='ignore').lower()
            
            patterns["has_json"] = '{' in text and '}' in text
            patterns["has_xml"] = '<' in text and '>' in text
            patterns["has_timestamps"] = bool(re.search(r'\d{10,13}', text))  # Unix timestamps
            patterns["has_ids"] = bool(re.search(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}', text))  # UUIDs
            
            # Binary header analysis
            if len(data) >= 4:
                header = data[:4]
                if header.isalnum() or header in [b'FLEX', b'HASP', b'CMET']:
                    patterns["has_binary_header"] = True
                    
        except Exception as e:
            self.logger.debug(f"Pattern extraction failed: {e}")
            
        return patterns
        
    def _parse_http_request(self, data: bytes) -> Dict[str, Any]:
        """Parse HTTP request for details"""
        details = {
            "method": "GET",
            "path": "/",
            "headers": {},
            "body": "",
            "query_params": {},
            "form_data": {}
        }
        
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            # Parse request line
            if lines:
                request_line = lines[0].split()
                if len(request_line) >= 2:
                    details["method"] = request_line[0]
                    details["path"] = request_line[1]
                    
            # Parse headers
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    details["headers"][key.strip().lower()] = value.strip()
                    
            # Parse body
            if body_start < len(lines):
                details["body"] = '\r\n'.join(lines[body_start:])
                
                # Try to parse as JSON
                try:
                    if details["body"].strip().startswith('{'):
                        json_data = json.loads(details["body"])
                        details["json_data"] = json_data
                except:
                    pass
                    
                # Try to parse as form data
                if 'application/x-www-form-urlencoded' in details["headers"].get("content-type", ""):
                    try:
                        form_pairs = details["body"].split('&')
                        for pair in form_pairs:
                            if '=' in pair:
                                key, value = pair.split('=', 1)
                                details["form_data"][key] = value
                    except:
                        pass
                        
        except Exception as e:
            self.logger.debug(f"HTTP parsing failed: {e}")
            
        return details
        
    def _generate_json_response_body(self, request_details: Dict[str, Any], 
                                   analysis: Dict[str, Any]) -> str:
        """Generate JSON response body"""
        try:
            response_data = {
                "status": "success",
                "timestamp": int(time.time()),
                "server": "intellicrack-license-server"
            }
            
            # Add request-specific fields
            if "has_product_info" in analysis["patterns"]:
                response_data["product_validation"] = "approved"
                response_data["license_type"] = "full"
                
            if "has_license_info" in analysis["patterns"]:
                response_data["license_status"] = "valid"
                response_data["expiry_date"] = "2025-12-31"
                response_data["features_enabled"] = ["all"]
                
            if "has_auth" in analysis["patterns"]:
                response_data["authentication"] = "successful"
                response_data["session_token"] = hashlib.md5(str(time.time()).encode()).hexdigest()
                
            # Mirror some request fields if present
            if request_details.get("json_data"):
                json_data = request_details["json_data"]
                if "product_id" in json_data:
                    response_data["product_id"] = json_data["product_id"]
                if "user_id" in json_data:
                    response_data["user_id"] = json_data["user_id"]
                if "client_id" in json_data:
                    response_data["client_id"] = json_data["client_id"]
                    
            return json.dumps(response_data, indent=2)
            
        except Exception as e:
            self.logger.error(f"JSON response generation failed: {e}")
            return '{"status": "success"}'
            
    def _generate_xml_response_body(self, request_details: Dict[str, Any],
                                  analysis: Dict[str, Any]) -> str:
        """Generate XML response body"""
        try:
            xml_response = '<?xml version="1.0" encoding="UTF-8"?>\n'
            xml_response += '<license_response>\n'
            xml_response += '  <status>success</status>\n'
            xml_response += f'  <timestamp>{int(time.time())}</timestamp>\n'
            xml_response += '  <server>intellicrack-license-server</server>\n'
            
            if "has_license_info" in analysis["patterns"]:
                xml_response += '  <license>\n'
                xml_response += '    <valid>true</valid>\n'
                xml_response += '    <expiry_date>2025-12-31</expiry_date>\n'
                xml_response += '    <features>all</features>\n'
                xml_response += '  </license>\n'
                
            xml_response += '</license_response>'
            
            return xml_response
            
        except Exception as e:
            self.logger.error(f"XML response generation failed: {e}")
            return '<?xml version="1.0"?><response><status>success</status></response>'
            
    def _get_authentic_server_name(self, context: ResponseContext) -> str:
        """Get authentic server name based on context"""
        try:
            # Map ports to typical server names
            port_server_map = {
                443: "Apache/2.4.41",
                80: "nginx/1.18.0",
                27000: "lmgrd/11.18",
                1947: "Sentinel RMS License Manager",
                22350: "CodeMeter Runtime Server",
                7788: "Adobe License Service",
                2080: "Autodesk License Service"
            }
            
            return port_server_map.get(context.target_port, "License-Server/1.0")
            
        except:
            return "License-Server/1.0"
            
    def _serialize_dict(self, data: Dict[str, Any]) -> bytes:
        """Serialize dictionary to bytes for binary protocols"""
        try:
            import struct
            serialized = bytearray()
            
            for key, value in data.items():
                key_bytes = key.encode('utf-8')
                
                if isinstance(value, str):
                    value_bytes = value.encode('utf-8')
                elif isinstance(value, int):
                    value_bytes = struct.pack('<I', value)
                elif isinstance(value, list):
                    value_bytes = str(value).encode('utf-8')
                else:
                    value_bytes = str(value).encode('utf-8')
                    
                serialized.extend(struct.pack('<H', len(key_bytes)))
                serialized.extend(key_bytes)
                serialized.extend(struct.pack('<H', len(value_bytes)))
                serialized.extend(value_bytes)
                
            return bytes(serialized)
            
        except Exception as e:
            self.logger.debug(f"Dictionary serialization failed: {e}")
            return b''
            
    def _generate_learned_response(self, context: ResponseContext, 
                                 client_profile: Dict[str, Any]) -> GeneratedResponse:
        """Generate response based on learned client patterns"""
        try:
            learned_patterns = client_profile["learned_patterns"]
            
            # Use most successful pattern for this client
            best_pattern = learned_patterns.get("most_successful", {})
            
            if best_pattern:
                # Generate response using learned pattern
                if best_pattern.get("response_type") == "http_success":
                    return self._generate_http_success_response(context)
                elif best_pattern.get("response_type") == "flexlm_success":
                    return self._generate_flexlm_success_response(context)
                # Add other learned patterns as needed
                
            # Fall back to adaptive if no learned patterns
            return self._adaptive_response_strategy(context)
            
        except Exception as e:
            self.logger.error(f"Learned response generation failed: {e}")
            return self._generate_fallback_response(context)
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get response generation statistics"""
        try:
            stats = {
                "total_responses_generated": len(self.learning_data),
                "cached_responses": len(self.response_cache),
                "tracked_clients": len(self.client_profiles),
                "protocols_supported": list(self.protocol_parsers.keys()),
                "strategies_available": list(self.strategies.keys()),
                "response_types_generated": {},
                "confidence_distribution": {"high": 0, "medium": 0, "low": 0}
            }
            
            # Analyze learning data
            for entry in self.learning_data:
                response_type = entry.get("response_type", "unknown")
                stats["response_types_generated"][response_type] = stats["response_types_generated"].get(response_type, 0) + 1
                
                confidence = entry.get("confidence", 0)
                if confidence >= 0.8:
                    stats["confidence_distribution"]["high"] += 1
                elif confidence >= 0.5:
                    stats["confidence_distribution"]["medium"] += 1
                else:
                    stats["confidence_distribution"]["low"] += 1
                    
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
            
    def clear_cache(self):
        """Clear response cache"""
        self.response_cache.clear()
        self.logger.info("Response cache cleared")
        
    def clear_learning_data(self):
        """Clear learning data"""
        self.learning_data.clear()
        self.client_profiles.clear()
        self.logger.info("Learning data cleared")
        
    def export_learning_data(self) -> Dict[str, Any]:
        """Export learning data for analysis"""
        return {
            "learning_data": self.learning_data.copy(),
            "client_profiles": self.client_profiles.copy(),
            "statistics": self.get_statistics()
        }
        
    def import_learning_data(self, data: Dict[str, Any]):
        """Import learning data"""
        try:
            if "learning_data" in data:
                self.learning_data = data["learning_data"]
            if "client_profiles" in data:
                self.client_profiles = data["client_profiles"]
            self.logger.info("Learning data imported successfully")
        except Exception as e:
            self.logger.error(f"Failed to import learning data: {e}")