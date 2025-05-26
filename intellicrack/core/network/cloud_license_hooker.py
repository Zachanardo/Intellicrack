"""
Cloud License Response Generator Module

This module provides automatic response generation for cloud-based license verification
requests. It analyzes license verification protocols and generates valid-looking responses
to bypass license checks using pattern matching, machine learning, and adaptive techniques.

Core Features:
- Multi-service support (Adobe, Autodesk, JetBrains, Microsoft)
- Automatic service identification through pattern matching
- Template-based response generation for JSON, XML, and binary formats
- Response caching for improved performance
- Learning mode for adapting to new license check patterns

Author: Intellicrack Team
License: MIT
"""

import copy
import datetime
import hashlib
import json
import logging
import random
import re
import string
from typing import Dict, List, Any, Optional, Union

try:
    from PyQt5.QtWidgets import QMessageBox
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False


class CloudLicenseResponseGenerator:
    """
    Automatic response generation for cloud license checks.

    This system analyzes cloud-based license verification requests and
    automatically generates valid-looking responses to bypass license checks.
    It uses pattern matching, machine learning, and adaptive techniques to
    handle various license verification protocols.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the cloud license response generator.

        Args:
            config: Configuration dictionary (optional)
        """
        self.logger = logging.getLogger(__name__)

        # Default configuration
        self.config = {
            'learning_mode': True,
            'response_cache_size': 100,
            'adaptive_mode': True,
            'success_patterns': [
                'success', 'valid', 'activated', 'authorized',
                'authenticated', 'approved', 'allowed', 'granted'
            ],
            'failure_patterns': [
                'error', 'invalid', 'expired', 'unauthorized',
                'unauthenticated', 'denied', 'rejected', 'failed'
            ]
        }

        # Update with provided configuration
        if config:
            self.config.update(config)

        # Initialize components
        self.response_templates: Dict[str, Dict[str, Any]] = {}
        self.response_cache: Dict[str, Dict[str, Any]] = {}
        self.request_patterns: Dict[str, Dict[str, Any]] = {}
        self.learned_patterns: Dict[str, Dict[str, Any]] = {}

        # Load response templates
        self._load_response_templates()

        # Load request patterns
        self._load_request_patterns()

    def _load_response_templates(self) -> None:
        """
        Load response templates for various cloud license services.
        """
        # Adobe Creative Cloud
        self.response_templates['adobe'] = {
            'json': {
                'status': 'SUCCESS',
                'message': 'License is valid',
                'expiry': '2099-12-31',
                'serial': '1234-5678-9012-3456-7890',
                'valid': True,
                'activated': True,
                'expired': False,
                'products': [
                    {'id': 'PHSP', 'name': 'Photoshop', 'status': 'ACTIVATED'},
                    {'id': 'ILST', 'name': 'Illustrator', 'status': 'ACTIVATED'},
                    {'id': 'AEFT', 'name': 'After Effects', 'status': 'ACTIVATED'}
                ]
            },
            'xml': """
                <response>
                    <status>SUCCESS</status>
                    <license>
                        <valid>true</valid>
                        <expired>false</expired>
                        <expiry>2099-12-31</expiry>
                        <serial>1234-5678-9012-3456-7890</serial>
                    </license>
                </response>
            """
        }

        # Autodesk
        self.response_templates['autodesk'] = {
            'json': {
                'status': 'success',
                'license': {
                    'status': 'ACTIVATED',
                    'type': 'PERMANENT',
                    'expiry': '2099-12-31'
                },
                'user': {
                    'name': 'Licensed User',
                    'email': 'user@example.com',
                    'type': 'PREMIUM'
                },
                'products': [
                    {'id': 'AUTOCAD', 'name': 'AutoCAD', 'status': 'ACTIVATED'},
                    {'id': '3DSMAX', 'name': '3ds Max', 'status': 'ACTIVATED'},
                    {'id': 'REVIT', 'name': 'Revit', 'status': 'ACTIVATED'}
                ]
            }
        }

        # JetBrains
        self.response_templates['jetbrains'] = {
            'json': {
                'licenseId': '1234567890',
                'licenseType': 'commercial',
                'evaluationLicense': False,
                'expired': False,
                'perpetualLicense': True,
                'errorCode': 0,
                'errorMessage': None,
                'licenseExpirationDate': '2099-12-31',
                'licenseExpirationDateMs': 4102444800000,
                'products': [
                    {'code': 'II', 'name': 'IntelliJ IDEA', 'status': 'ACTIVATED'},
                    {'code': 'PS', 'name': 'PhpStorm', 'status': 'ACTIVATED'},
                    {'code': 'WS', 'name': 'WebStorm', 'status': 'ACTIVATED'}
                ]
            }
        }

        # Microsoft
        self.response_templates['microsoft'] = {
            'json': {
                'status': 'licensed',
                'licenseStatus': 'licensed',
                'gracePeriodDays': 0,
                'errorCode': 0,
                'errorMessage': None,
                'products': [
                    {'id': 'O365', 'name': 'Office 365', 'status': 'ACTIVATED'},
                    {'id': 'WINPRO', 'name': 'Windows 10 Pro', 'status': 'ACTIVATED'},
                    {'id': 'VISIO', 'name': 'Visio', 'status': 'ACTIVATED'}
                ]
            }
        }

        # Generic template
        self.response_templates['generic'] = {
            'json': {
                'status': 'success',
                'license': 'valid',
                'expiry': '2099-12-31',
                'message': 'License is valid'
            },
            'xml': """
                <response>
                    <status>success</status>
                    <license>valid</license>
                    <expiry>2099-12-31</expiry>
                    <message>License is valid</message>
                </response>
            """
        }

    def _load_request_patterns(self) -> None:
        """
        Load request patterns for identifying license check requests.
        """
        # Adobe Creative Cloud
        self.request_patterns['adobe'] = {
            'urls': [
                'licensing.adobe.com',
                'lm.licenses.adobe.com',
                'activate.adobe.com',
                'api.licenses.adobe.com'
            ],
            'headers': [
                'X-Adobe-App-Id',
                'X-Adobe-Client-Id'
            ],
            'body_patterns': [
                'license',
                'activation',
                'validate',
                'check'
            ]
        }

        # Autodesk
        self.request_patterns['autodesk'] = {
            'urls': [
                'lm.autodesk.com',
                'lmaccess.autodesk.com',
                'lmlicensing.autodesk.com',
                'lm-autocad.autodesk.com'
            ],
            'headers': [
                'X-Autodesk-Client',
                'X-Autodesk-Product'
            ],
            'body_patterns': [
                'license',
                'activation',
                'validate',
                'check'
            ]
        }

        # JetBrains
        self.request_patterns['jetbrains'] = {
            'urls': [
                'license.jetbrains.com',
                'account.jetbrains.com',
                'data.services.jetbrains.com'
            ],
            'headers': [
                'X-JetBrains-Client',
                'X-JetBrains-Product'
            ],
            'body_patterns': [
                'license',
                'activation',
                'validate',
                'check'
            ]
        }

        # Microsoft
        self.request_patterns['microsoft'] = {
            'urls': [
                'licensing.mp.microsoft.com',
                'activation.microsoft.com',
                'kms.microsoft.com',
                'kms.core.windows.net'
            ],
            'headers': [
                'X-Microsoft-Client',
                'X-Microsoft-Product'
            ],
            'body_patterns': [
                'license',
                'activation',
                'validate',
                'check'
            ]
        }

    def identify_service(self, request: Dict[str, Any]) -> str:
        """
        Identify the cloud license service from the request.

        Args:
            request: Request data (dict with url, headers, body)

        Returns:
            str: Service name, or 'generic' if not identified
        """
        # Check each service pattern
        for service, patterns in self.request_patterns.items():
            score = 0

            # Check URL
            if any(url in request['url'].lower() for url in patterns['urls']):
                score += 3

            # Check headers
            for header in patterns['headers']:
                if header.lower() in [h.lower() for h in request['headers']]:
                    score += 1

            # Check body patterns
            if request.get('body'):
                for pattern in patterns['body_patterns']:
                    if pattern.lower() in request['body'].lower():
                        score += 1

            if score >= 3:
                return service

        # Default to generic service
        return 'generic'

    def generate_response(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a response for a cloud license check request.

        Args:
            request: Request data (dict with url, headers, body)

        Returns:
            dict: Response data (status_code, headers, body)
        """
        # Check cache first
        cache_key = self._get_cache_key(request)
        if cache_key in self.response_cache:
            self.logger.info(f"Using cached response for {request['url']}")
            return self.response_cache[cache_key]

        # Identify service
        service = self.identify_service(request)
        self.logger.info(f"Identified service: {service}")

        # Determine response format
        response_format = self._determine_response_format(request)

        # Generate response
        if response_format == 'json':
            response = self._generate_json_response(service, request)
        elif response_format == 'xml':
            response = self._generate_xml_response(service, request)
        else:
            response = self._generate_binary_response(service, request)

        # Cache response
        self.response_cache[cache_key] = response

        # Trim cache if needed
        if len(self.response_cache) > self.config['response_cache_size']:
            # Remove oldest entry
            oldest_key = next(iter(self.response_cache))
            del self.response_cache[oldest_key]

        return response

    def _get_cache_key(self, request: Dict[str, Any]) -> str:
        """
        Generate a cache key for a request.

        Args:
            request: Request data

        Returns:
            str: Cache key
        """
        # Create a string representation of the request
        request_str = f"{request['url']}|{request.get('method', 'GET')}|{str(request['headers'])}|{request.get('body', '')}"

        # Generate hash
        return hashlib.md5(request_str.encode('utf-8')).hexdigest()

    def _determine_response_format(self, request: Dict[str, Any]) -> str:
        """
        Determine the response format based on the request.

        Args:
            request: Request data

        Returns:
            str: Response format ('json', 'xml', or 'binary')
        """
        # Check Content-Type header
        content_type = None
        for header, value in request['headers'].items():
            if header.lower() == 'content-type':
                content_type = value.lower()
                break

        if content_type:
            if 'json' in content_type:
                return 'json'
            elif 'xml' in content_type:
                return 'xml'

        # Check Accept header
        accept = None
        for header, value in request['headers'].items():
            if header.lower() == 'accept':
                accept = value.lower()
                break

        if accept:
            if 'json' in accept:
                return 'json'
            elif 'xml' in accept:
                return 'xml'

        # Check request body
        if request.get('body'):
            if request['body'].startswith('{') or request['body'].startswith('['):
                return 'json'
            elif request['body'].startswith('<'):
                return 'xml'

        # Default to JSON
        return 'json'

    def _generate_json_response(self, service: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a JSON response for a cloud license check request.

        Args:
            service: Service name
            request: Request data

        Returns:
            dict: Response data
        """
        # Get template
        if service in self.response_templates and 'json' in self.response_templates[service]:
            template = self.response_templates[service]['json']
        else:
            template = self.response_templates['generic']['json']

        # Customize template based on request
        response_body = self._customize_template(template, request)

        # Convert to JSON string
        response_body_str = json.dumps(response_body)

        # Create response
        response = {
            'status_code': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Content-Length': str(len(response_body_str))
            },
            'body': response_body_str
        }

        return response

    def _generate_xml_response(self, service: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an XML response for a cloud license check request.

        Args:
            service: Service name
            request: Request data

        Returns:
            dict: Response data
        """
        # Get template
        if service in self.response_templates and 'xml' in self.response_templates[service]:
            template = self.response_templates[service]['xml']
        else:
            template = self.response_templates['generic']['xml']

        # Customize template
        response_body = template

        # Create response
        response = {
            'status_code': 200,
            'headers': {
                'Content-Type': 'application/xml',
                'Content-Length': str(len(response_body))
            },
            'body': response_body
        }

        return response

    def _generate_binary_response(self, service: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a binary response for a cloud license check request.

        Args:
            service: Service name
            request: Request data

        Returns:
            dict: Response data
        """
        # Create a simple binary response
        response_body = b'\x01\x00\x01\x00\x00\x01\x00\x01'

        # Create response
        response = {
            'status_code': 200,
            'headers': {
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(len(response_body))
            },
            'body': response_body
        }

        return response

    def _customize_template(self, template: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Customize a response template based on the request.

        Args:
            template: Template dictionary
            request: Request data

        Returns:
            dict: Customized template
        """
        # Create a deep copy of the template
        result = copy.deepcopy(template)

        # Extract information from request
        product_id = None
        user_id = None

        # Try to parse request body as JSON
        if request.get('body') and request['body'].startswith('{'):
            try:
                body_json = json.loads(request['body'])

                # Extract product ID
                if 'productId' in body_json:
                    product_id = body_json['productId']
                elif 'product' in body_json:
                    product_id = body_json['product']

                # Extract user ID
                if 'userId' in body_json:
                    user_id = body_json['userId']
                elif 'user' in body_json:
                    user_id = body_json['user']

            except:
                pass

        # Extract from URL
        if not product_id:
            # Try to extract from URL
            product_match = re.search(r'product[=/]([^&/]+)', request['url'])
            if product_match:
                product_id = product_match.group(1)

        if not user_id:
            # Try to extract from URL
            user_match = re.search(r'user[=/]([^&/]+)', request['url'])
            if user_match:
                user_id = user_match.group(1)

        # Customize template with extracted information
        if product_id and 'products' in result:
            # Add product to products list if not already present
            product_found = False
            for product in result['products']:
                if product['id'] == product_id or product['name'] == product_id:
                    product_found = True
                    break

            if not product_found:
                result['products'].append({
                    'id': product_id,
                    'name': product_id,
                    'status': 'ACTIVATED'
                })

        if user_id and 'user' in result:
            result['user']['id'] = user_id

        # Generate random license ID if not present
        if 'licenseId' not in result:
            result['licenseId'] = ''.join(random.choices(string.digits, k=10))

        # Set current date for issued date if not present
        if 'issuedDate' not in result:
            result['issuedDate'] = datetime.datetime.now().strftime('%Y-%m-%d')

        return result

    def learn_from_request(self, request: Dict[str, Any], response: Dict[str, Any]) -> bool:
        """
        Learn from a successful license check request-response pair.

        Args:
            request: Request data
            response: Response data

        Returns:
            bool: True if learned successfully, False otherwise
        """
        if not self.config['learning_mode']:
            return False

        try:
            # Identify service
            service = self.identify_service(request)

            # Check if response indicates success
            is_success = self._is_success_response(response)

            if is_success:
                # Extract patterns from request
                self._extract_patterns(service, request)

                # Extract response template
                self._extract_response_template(service, request, response)

                self.logger.info(f"Learned from successful {service} license check")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Error learning from request: {e}")
            return False

    def _is_success_response(self, response: Dict[str, Any]) -> bool:
        """
        Check if a response indicates a successful license check.

        Args:
            response: Response data

        Returns:
            bool: True if success, False otherwise
        """
        # Check status code
        if response['status_code'] != 200:
            return False

        # Check for success patterns in body
        body = response['body']
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')

        # Check for success patterns
        for pattern in self.config['success_patterns']:
            if pattern.lower() in body.lower():
                return True

        # Check for failure patterns
        for pattern in self.config['failure_patterns']:
            if pattern.lower() in body.lower():
                return False

        # Default to success
        return True

    def _extract_patterns(self, service: str, request: Dict[str, Any]) -> None:
        """
        Extract patterns from a request.

        Args:
            service: Service name
            request: Request data
        """
        # Initialize learned patterns for service if not exists
        if service not in self.learned_patterns:
            self.learned_patterns[service] = {
                'urls': set(),
                'headers': set(),
                'body_patterns': set()
            }

        # Extract URL patterns
        url_parts = request['url'].split('/')
        for part in url_parts:
            if len(part) > 5 and '.' in part:
                self.learned_patterns[service]['urls'].add(part)

        # Extract header patterns
        for header in request['headers']:
            if header.startswith('X-'):
                self.learned_patterns[service]['headers'].add(header)

        # Extract body patterns
        if request.get('body'):
            # Look for keywords
            keywords = ['license', 'activation', 'validate', 'check', 'auth', 'key']
            for keyword in keywords:
                if keyword.lower() in request['body'].lower():
                    self.learned_patterns[service]['body_patterns'].add(keyword)

    def _extract_response_template(self, service: str, request: Dict[str, Any], response: Dict[str, Any]) -> None:
        """
        Extract a response template from a successful response.

        Args:
            service: Service name
            request: Request data
            response: Response data
        """
        # Determine response format
        content_type = None
        for header, value in response['headers'].items():
            if header.lower() == 'content-type':
                content_type = value.lower()
                break

        # Extract template based on format
        if content_type and 'json' in content_type:
            self._extract_json_template(service, response)
        elif content_type and 'xml' in content_type:
            self._extract_xml_template(service, response)

    def _extract_json_template(self, service: str, response: Dict[str, Any]) -> None:
        """
        Extract a JSON template from a response.

        Args:
            service: Service name
            response: Response data
        """
        try:
            # Parse JSON
            body = response['body']
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')

            template = json.loads(body)

            # Store template
            if service not in self.response_templates:
                self.response_templates[service] = {}

            self.response_templates[service]['json'] = template

        except Exception as e:
            self.logger.error(f"Error extracting JSON template: {e}")

    def _extract_xml_template(self, service: str, response: Dict[str, Any]) -> None:
        """
        Extract an XML template from a response.

        Args:
            service: Service name
            response: Response data
        """
        try:
            # Get XML
            body = response['body']
            if isinstance(body, bytes):
                body = body.decode('utf-8', errors='ignore')

            # Store template
            if service not in self.response_templates:
                self.response_templates[service] = {}

            self.response_templates[service]['xml'] = body

        except Exception as e:
            self.logger.error(f"Error extracting XML template: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get generator statistics.

        Returns:
            dict: Statistics about the generator
        """
        return {
            'supported_services': list(self.request_patterns.keys()),
            'cached_responses': len(self.response_cache),
            'learned_patterns': len(self.learned_patterns),
            'learning_mode': self.config['learning_mode'],
            'cache_size': self.config['response_cache_size']
        }

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self.response_cache.clear()
        self.logger.info("Cleared response cache")

    def clear_learned_patterns(self) -> None:
        """Clear learned patterns."""
        self.learned_patterns.clear()
        self.logger.info("Cleared learned patterns")


def run_cloud_license_generator(app: Any) -> None:
    """
    Run the cloud license response generator.

    Args:
        app: Application instance
    """
    if hasattr(app, 'update_output'):
        app.update_output.emit("log_message([Cloud] Starting cloud license response generator...)")

    # Create generator
    generator = CloudLicenseResponseGenerator()

    # Handle learning mode selection if PyQt5 is available
    learning_mode = True
    if PYQT5_AVAILABLE:
        learning_mode = QMessageBox.question(
            app,
            "Learning Mode",
            "Enable learning mode? (Learns from successful license checks)",
            QMessageBox.Yes | QMessageBox.No
        ) == QMessageBox.Yes

    generator.config['learning_mode'] = learning_mode

    # Store generator instance in app
    app.cloud_generator = generator

    if hasattr(app, 'update_output'):
        app.update_output.emit("log_message([Cloud] Cloud license response generator started)")
        app.update_output.emit(f"log_message([Cloud] Learning mode: {learning_mode})")

    # Add to analyze results
    if not hasattr(app, "analyze_results"):
        app.analyze_results = []

    app.analyze_results.append("\n=== CLOUD LICENSE RESPONSE GENERATOR ===")
    app.analyze_results.append(f"Learning mode: {learning_mode}")
    app.analyze_results.append("\nSupported services:")
    for service in generator.request_patterns.keys():
        app.analyze_results.append(f"- {service.upper()}")

    app.analyze_results.append("\nFeatures:")
    app.analyze_results.append("- Automatic response generation for cloud license checks")
    app.analyze_results.append("- Pattern matching for service identification")
    app.analyze_results.append("- Template-based response generation")
    app.analyze_results.append("- Response caching for improved performance")
    if learning_mode:
        app.analyze_results.append("- Learning mode for adapting to new license check patterns")

    app.analyze_results.append("\nTo use the cloud license response generator:")
    app.analyze_results.append("1. Use with the SSL/TLS interceptor or network license server emulator")
    app.analyze_results.append("2. The generator will automatically create valid responses for license checks")
    app.analyze_results.append("3. Responses are customized based on the specific service and request")


# Export the main classes and functions
__all__ = [
    'CloudLicenseResponseGenerator',
    'run_cloud_license_generator'
]