"""
Encoder Engine for Payload Generation

Provides multiple encoding schemes for payload obfuscation
and evasion including XOR, Base64, custom algorithms.
"""

import base64
import logging
import random
import string
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class EncoderEngine:
    """
    Advanced payload encoding engine with multiple encoding schemes
    and anti-analysis capabilities.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.EncoderEngine")

        # Available encoding schemes
        self.encoders = {
            'xor': self._xor_encode,
            'base64': self._base64_encode,
            'hex': self._hex_encode,
            'rot13': self._rot13_encode,
            'custom_shift': self._custom_shift_encode,
            'multi_xor': self._multi_xor_encode,
            'alpha_mixed': self._alpha_mixed_encode,
            'reverse': self._reverse_encode,
            'substitution': self._substitution_encode,
            'bit_manipulation': self._bit_manipulation_encode
        }

        self.decoders = {
            'xor': self._xor_decode,
            'base64': self._base64_decode,
            'hex': self._hex_decode,
            'rot13': self._rot13_decode,
            'custom_shift': self._custom_shift_decode,
            'multi_xor': self._multi_xor_decode,
            'alpha_mixed': self._alpha_mixed_decode,
            'reverse': self._reverse_decode,
            'substitution': self._substitution_decode,
            'bit_manipulation': self._bit_manipulation_decode
        }

    def encode_payload(self, payload: bytes, encoding_scheme: str, encoding_params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Encode payload using specified encoding scheme.
        
        Args:
            payload: Raw payload bytes
            encoding_scheme: Name of encoding scheme to use
            encoding_params: Parameters specific to encoding scheme
            
        Returns:
            Dictionary containing encoded payload and decoding information
        """
        try:
            if encoding_scheme not in self.encoders:
                raise ValueError(f"Unknown encoding scheme: {encoding_scheme}")

            self.logger.info(f"Encoding payload using {encoding_scheme} scheme")

            encoder_func = self.encoders[encoding_scheme]
            encoded_data, decode_info = encoder_func(payload, encoding_params or {})

            result = {
                'encoded_payload': encoded_data,
                'encoding_scheme': encoding_scheme,
                'decode_info': decode_info,
                'original_size': len(payload),
                'encoded_size': len(encoded_data) if isinstance(encoded_data, bytes) else len(str(encoded_data)),
                'decoder_stub': self._generate_decoder_stub(encoding_scheme, decode_info)
            }

            self.logger.info(f"Encoded payload: {len(payload)} -> {result['encoded_size']} bytes")
            return result

        except Exception as e:
            self.logger.error(f"Payload encoding failed: {e}")
            raise

    def multi_encode_payload(self, payload: bytes, encoding_schemes: List[str],
                           encoding_params: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Apply multiple encoding schemes in sequence.
        
        Args:
            payload: Raw payload bytes
            encoding_schemes: List of encoding schemes to apply
            encoding_params: List of parameters for each encoding scheme
            
        Returns:
            Dictionary containing multi-encoded payload and decoding chain
        """
        try:
            self.logger.info(f"Multi-encoding payload with {len(encoding_schemes)} schemes")

            current_payload = payload
            decode_chain = []

            if encoding_params is None:
                encoding_params = [{}] * len(encoding_schemes)

            # Apply encodings in sequence
            for i, scheme in enumerate(encoding_schemes):
                params = encoding_params[i] if i < len(encoding_params) else {}
                result = self.encode_payload(current_payload, scheme, params)

                current_payload = result['encoded_payload']
                if isinstance(current_payload, str):
                    current_payload = current_payload.encode('utf-8')

                decode_chain.append({
                    'scheme': scheme,
                    'decode_info': result['decode_info']
                })

            # Generate combined decoder
            combined_decoder = self._generate_multi_decoder_stub(decode_chain)

            return {
                'encoded_payload': current_payload,
                'encoding_schemes': encoding_schemes,
                'decode_chain': decode_chain,
                'original_size': len(payload),
                'final_size': len(current_payload),
                'decoder_stub': combined_decoder
            }

        except Exception as e:
            self.logger.error(f"Multi-encoding failed: {e}")
            raise

    def decode_payload(self, encoded_data: Any, encoding_scheme: str, decode_info: Dict[str, Any]) -> bytes:
        """
        Decode payload using specified decoding information.
        
        Args:
            encoded_data: Encoded payload data
            encoding_scheme: Name of encoding scheme used
            decode_info: Decoding parameters
            
        Returns:
            Decoded payload bytes
        """
        try:
            if encoding_scheme not in self.decoders:
                raise ValueError(f"Unknown encoding scheme: {encoding_scheme}")

            decoder_func = self.decoders[encoding_scheme]
            decoded_payload = decoder_func(encoded_data, decode_info)

            self.logger.info(f"Decoded payload using {encoding_scheme}")
            return decoded_payload

        except Exception as e:
            self.logger.error(f"Payload decoding failed: {e}")
            raise

    # Encoding implementations

    def _xor_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """XOR encoding with single or multi-byte key."""
        key = params.get('key')
        if key is None:
            key = bytes([random.randint(1, 255)])  # Avoid null byte
        elif isinstance(key, int):
            key = bytes([key])
        elif isinstance(key, str):
            key = key.encode('utf-8')

        encoded = bytearray()
        for i, byte in enumerate(payload):
            encoded.append(byte ^ key[i % len(key)])

        return bytes(encoded), {'key': key}

    def _xor_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """XOR decoding."""
        key = decode_info['key']
        decoded = bytearray()
        for i, byte in enumerate(encoded_data):
            decoded.append(byte ^ key[i % len(key)])
        return bytes(decoded)

    def _base64_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Base64 encoding with optional custom alphabet."""
        custom_alphabet = params.get('alphabet')
        if custom_alphabet:
            # Custom base64 with different alphabet
            standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            encoded = base64.b64encode(payload).decode('utf-8')
            # Translate to custom alphabet
            translation = str.maketrans(standard, custom_alphabet)
            encoded = encoded.translate(translation)
            return encoded, {'alphabet': custom_alphabet}
        else:
            encoded = base64.b64encode(payload).decode('utf-8')
            return encoded, {}

    def _base64_decode(self, encoded_data: str, decode_info: Dict[str, Any]) -> bytes:
        """Base64 decoding."""
        custom_alphabet = decode_info.get('alphabet')
        if custom_alphabet:
            standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            translation = str.maketrans(custom_alphabet, standard)
            encoded_data = encoded_data.translate(translation)
        return base64.b64decode(encoded_data)

    def _hex_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Hexadecimal encoding with optional custom formatting."""
        uppercase = params.get('uppercase', False)
        separator = params.get('separator', '')
        prefix = params.get('prefix', '')

        hex_str = payload.hex()
        if uppercase:
            hex_str = hex_str.upper()

        if separator:
            hex_str = separator.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

        if prefix:
            hex_str = prefix + hex_str

        return hex_str, {'uppercase': uppercase, 'separator': separator, 'prefix': prefix}

    def _hex_decode(self, encoded_data: str, decode_info: Dict[str, Any]) -> bytes:
        """Hexadecimal decoding."""
        separator = decode_info.get('separator', '')
        prefix = decode_info.get('prefix', '')

        hex_str = encoded_data
        if prefix:
            hex_str = hex_str[len(prefix):]
        if separator:
            hex_str = hex_str.replace(separator, '')

        return bytes.fromhex(hex_str)

    def _rot13_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """ROT13 encoding for alphabetic characters."""
        shift = params.get('shift', 13)

        result = []
        for byte in payload:
            char = chr(byte)
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base + shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)

        return ''.join(result), {'shift': shift}

    def _rot13_decode(self, encoded_data: str, decode_info: Dict[str, Any]) -> bytes:
        """ROT13 decoding."""
        shift = decode_info.get('shift', 13)

        result = []
        for char in encoded_data:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - base - shift) % 26 + base
                result.append(chr(shifted))
            else:
                result.append(char)

        return ''.join(result).encode('utf-8')

    def _custom_shift_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Custom shift cipher with variable shift per byte."""
        base_shift = params.get('base_shift', random.randint(1, 255))
        shift_increment = params.get('shift_increment', random.randint(1, 7))

        encoded = bytearray()
        current_shift = base_shift

        for byte in payload:
            encoded_byte = (byte + current_shift) % 256
            encoded.append(encoded_byte)
            current_shift = (current_shift + shift_increment) % 256

        return bytes(encoded), {'base_shift': base_shift, 'shift_increment': shift_increment}

    def _custom_shift_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """Custom shift cipher decoding."""
        base_shift = decode_info['base_shift']
        shift_increment = decode_info['shift_increment']

        decoded = bytearray()
        current_shift = base_shift

        for byte in encoded_data:
            decoded_byte = (byte - current_shift) % 256
            decoded.append(decoded_byte)
            current_shift = (current_shift + shift_increment) % 256

        return bytes(decoded)

    def _multi_xor_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Multi-pass XOR with different keys."""
        num_passes = params.get('passes', 3)
        keys = params.get('keys')

        if keys is None:
            keys = [bytes([random.randint(1, 255)]) for _ in range(num_passes)]

        current_data = payload
        for key in keys:
            encoded = bytearray()
            for i, byte in enumerate(current_data):
                encoded.append(byte ^ key[i % len(key)])
            current_data = bytes(encoded)

        return current_data, {'keys': keys}

    def _multi_xor_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """Multi-pass XOR decoding."""
        keys = decode_info['keys']

        current_data = encoded_data
        # Decode in reverse order
        for key in reversed(keys):
            decoded = bytearray()
            for i, byte in enumerate(current_data):
                decoded.append(byte ^ key[i % len(key)])
            current_data = bytes(decoded)

        return current_data

    def _alpha_mixed_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Encode as mixed alphanumeric characters."""
        charset = params.get('charset', string.ascii_letters + string.digits)

        # Convert bytes to base representation using charset
        base = len(charset)
        result = []

        for byte in payload:
            # Convert byte to base representation
            if byte == 0:
                result.append(charset[0])
            else:
                chars = []
                while byte > 0:
                    chars.append(charset[byte % base])
                    byte //= base
                result.append(''.join(reversed(chars)))
            result.append('|')  # Separator

        encoded = ''.join(result).rstrip('|')
        return encoded, {'charset': charset}

    def _alpha_mixed_decode(self, encoded_data: str, decode_info: Dict[str, Any]) -> bytes:
        """Decode from mixed alphanumeric characters."""
        charset = decode_info['charset']
        base = len(charset)

        decoded = bytearray()
        for chunk in encoded_data.split('|'):
            if not chunk:
                continue

            # Convert from base representation
            value = 0
            for char in chunk:
                value = value * base + charset.index(char)
            decoded.append(value % 256)

        return bytes(decoded)

    def _reverse_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Simple reversal with optional block-wise reversal."""
        block_size = params.get('block_size', 0)

        if block_size > 0:
            # Reverse in blocks
            result = bytearray()
            for i in range(0, len(payload), block_size):
                block = payload[i:i+block_size]
                result.extend(reversed(block))
            return bytes(result), {'block_size': block_size}
        else:
            # Simple full reversal
            return bytes(reversed(payload)), {'block_size': 0}

    def _reverse_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """Reverse decoding."""
        block_size = decode_info.get('block_size', 0)

        if block_size > 0:
            # Reverse in blocks
            result = bytearray()
            for i in range(0, len(encoded_data), block_size):
                block = encoded_data[i:i+block_size]
                result.extend(reversed(block))
            return bytes(result)
        else:
            # Simple full reversal
            return bytes(reversed(encoded_data))

    def _substitution_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Substitution cipher with custom mapping."""
        mapping = params.get('mapping')

        if mapping is None:
            # Generate random substitution mapping
            mapping = list(range(256))
            random.shuffle(mapping)

        encoded = bytearray()
        for byte in payload:
            encoded.append(mapping[byte])

        return bytes(encoded), {'mapping': mapping}

    def _substitution_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """Substitution cipher decoding."""
        mapping = decode_info['mapping']

        # Create reverse mapping
        reverse_mapping = [0] * 256
        for i, mapped_value in enumerate(mapping):
            reverse_mapping[mapped_value] = i

        decoded = bytearray()
        for byte in encoded_data:
            decoded.append(reverse_mapping[byte])

        return bytes(decoded)

    def _bit_manipulation_encode(self, payload: bytes, params: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Bit-level manipulation encoding."""
        operation = params.get('operation', 'flip')  # flip, rotate, swap
        param_value = params.get('value', random.randint(1, 7))

        encoded = bytearray()

        for byte in payload:
            if operation == 'flip':
                # Flip specific bit
                encoded_byte = byte ^ (1 << (param_value % 8))
            elif operation == 'rotate':
                # Rotate bits
                encoded_byte = ((byte << param_value) | (byte >> (8 - param_value))) & 0xFF
            elif operation == 'swap':
                # Swap nibbles or specific bits
                if param_value == 4:  # Swap nibbles
                    encoded_byte = ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)
                else:
                    encoded_byte = byte  # No change for other values
            else:
                encoded_byte = byte

            encoded.append(encoded_byte)

        return bytes(encoded), {'operation': operation, 'value': param_value}

    def _bit_manipulation_decode(self, encoded_data: bytes, decode_info: Dict[str, Any]) -> bytes:
        """Bit manipulation decoding."""
        operation = decode_info['operation']
        param_value = decode_info['value']

        decoded = bytearray()

        for byte in encoded_data:
            if operation == 'flip':
                # Flip the same bit back
                decoded_byte = byte ^ (1 << (param_value % 8))
            elif operation == 'rotate':
                # Rotate bits in opposite direction
                decoded_byte = ((byte >> param_value) | (byte << (8 - param_value))) & 0xFF
            elif operation == 'swap':
                # Swap back
                if param_value == 4:  # Swap nibbles back
                    decoded_byte = ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)
                else:
                    decoded_byte = byte
            else:
                decoded_byte = byte

            decoded.append(decoded_byte)

        return bytes(decoded)

    def _generate_decoder_stub(self, encoding_scheme: str, decode_info: Dict[str, Any]) -> str:
        """Generate decoder stub code for specific encoding scheme."""
        if encoding_scheme == 'xor':
            key = decode_info['key']
            key_bytes = ', '.join(f'0x{b:02x}' for b in key)
            return f'''
# XOR Decoder
key = [{key_bytes}]
decoded = bytearray()
for i, byte in enumerate(encoded_data):
    decoded.append(byte ^ key[i % len(key)])
payload = bytes(decoded)
'''
        elif encoding_scheme == 'base64':
            alphabet = decode_info.get('alphabet')
            if alphabet:
                return f'''
# Custom Base64 Decoder
import base64
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom = "{alphabet}"
translation = str.maketrans(custom, standard)
decoded_data = encoded_data.translate(translation)
payload = base64.b64decode(decoded_data)
'''
            else:
                return '''
# Base64 Decoder
import base64
payload = base64.b64decode(encoded_data)
'''
        elif encoding_scheme == 'custom_shift':
            base_shift = decode_info['base_shift']
            shift_increment = decode_info['shift_increment']
            return f'''
# Custom Shift Decoder
decoded = bytearray()
current_shift = {base_shift}
for byte in encoded_data:
    decoded_byte = (byte - current_shift) % 256
    decoded.append(decoded_byte)
    current_shift = (current_shift + {shift_increment}) % 256
payload = bytes(decoded)
'''
        else:
            return f'''
# Generic Decoder for {encoding_scheme}
# Decoding logic would be implemented here
payload = encoded_data
'''

    def _generate_multi_decoder_stub(self, decode_chain: List[Dict[str, Any]]) -> str:
        """Generate decoder stub for multi-encoded payload."""
        decoder_code = "# Multi-stage Decoder\ncurrent_data = encoded_data\n\n"

        # Generate decoding steps in reverse order
        for step in reversed(decode_chain):
            scheme = step['scheme']
            decode_info = step['decode_info']

            step_code = self._generate_decoder_stub(scheme, decode_info)
            # Adapt the code to work on current_data
            step_code = step_code.replace('encoded_data', 'current_data')
            step_code = step_code.replace('payload = ', 'current_data = ')

            decoder_code += step_code + "\n"

        decoder_code += "payload = current_data\n"
        return decoder_code

    def get_random_encoding_scheme(self) -> str:
        """Get a random encoding scheme."""
        return random.choice(list(self.encoders.keys()))

    def get_encoding_schemes(self) -> List[str]:
        """Get list of available encoding schemes."""
        return list(self.encoders.keys())

    def benchmark_encoding_schemes(self, test_payload: bytes) -> Dict[str, Dict[str, Any]]:
        """Benchmark different encoding schemes."""
        results = {}

        for scheme in self.encoders.keys():
            try:
                import time
                start_time = time.time()

                result = self.encode_payload(test_payload, scheme)

                encode_time = time.time() - start_time

                # Test decoding
                start_time = time.time()
                decoded = self.decode_payload(
                    result['encoded_payload'],
                    scheme,
                    result['decode_info']
                )
                decode_time = time.time() - start_time

                # Verify correctness
                correct = decoded == test_payload

                results[scheme] = {
                    'encode_time': encode_time,
                    'decode_time': decode_time,
                    'size_ratio': result['encoded_size'] / len(test_payload),
                    'correct': correct,
                    'encoded_size': result['encoded_size']
                }

            except Exception as e:
                results[scheme] = {'error': str(e)}

        return results
