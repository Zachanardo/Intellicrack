"""
String Obfuscation Detection Engine

Specialized detection for string and data obfuscation techniques including:
- String encryption patterns
- XOR obfuscation
- Base64 and custom encoding
- Dynamic string construction
- Runtime decryption routines

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import base64
import logging
import numpy as np
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ....utils.logger import get_logger

logger = get_logger(__name__)

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


@dataclass
class StringPattern:
    """Detected string obfuscation pattern"""
    address: int
    string_data: str
    pattern_type: str
    confidence: float
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'string_data': self.string_data[:100],  # Limit display length
            'pattern_type': self.pattern_type,
            'confidence': self.confidence,
            'metadata': self.metadata
        }


@dataclass
class EncryptionAnalysis:
    """String encryption analysis results"""
    total_strings: int
    encrypted_count: int
    high_entropy_count: int
    encoding_schemes: List[str]
    encryption_patterns: List[StringPattern]
    entropy_distribution: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_strings': self.total_strings,
            'encrypted_count': self.encrypted_count,
            'high_entropy_count': self.high_entropy_count,
            'encoding_schemes': self.encoding_schemes,
            'encryption_patterns': [p.to_dict() for p in self.encryption_patterns],
            'entropy_distribution': self.entropy_distribution
        }


class StringObfuscationDetector:
    """Advanced string obfuscation detection engine"""
    
    def __init__(self, r2_session: Optional[Any] = None):
        """Initialize string obfuscation detector
        
        Args:
            r2_session: Optional radare2 session
        """
        self.r2 = r2_session
        self.logger = logger
        
        # Detection thresholds
        self.high_entropy_threshold = 6.5
        self.encryption_confidence_threshold = 0.6
        self.min_string_length = 4
        
        # Common XOR keys for testing
        self.common_xor_keys = [
            0x01, 0x13, 0x37, 0x42, 0x7F, 0xAA, 0xFF,
            *range(1, 256, 17)  # Additional test keys
        ]
    
    def analyze_string_obfuscation(self) -> EncryptionAnalysis:
        """Perform comprehensive string obfuscation analysis
        
        Returns:
            Complete string obfuscation analysis results
        """
        if not self.r2:
            return EncryptionAnalysis(0, 0, 0, [], [], {})
        
        try:
            # Get all strings from binary
            strings = self.r2.cmdj("izj") or []
            
            total_strings = len(strings)
            encrypted_count = 0
            high_entropy_count = 0
            encoding_schemes = set()
            encryption_patterns = []
            entropy_distribution = {}
            
            for string_info in strings:
                string_data = string_info.get('string', '')
                string_addr = string_info.get('vaddr', 0)
                
                if len(string_data) < self.min_string_length:
                    continue
                
                # Calculate string entropy
                entropy = self._calculate_shannon_entropy(string_data)
                entropy_distribution[f"0x{string_addr:x}"] = entropy
                
                # High entropy indicates possible encryption
                if entropy > self.high_entropy_threshold:
                    high_entropy_count += 1
                    
                    # Analyze encryption pattern
                    pattern = self._analyze_string_encryption(string_data, string_addr, entropy)
                    if pattern and pattern.confidence > self.encryption_confidence_threshold:
                        encrypted_count += 1
                        encryption_patterns.append(pattern)
                
                # Detect encoding schemes
                encoding = self._detect_encoding_scheme(string_data)
                if encoding:
                    encoding_schemes.add(encoding)
            
            return EncryptionAnalysis(
                total_strings=total_strings,
                encrypted_count=encrypted_count,
                high_entropy_count=high_entropy_count,
                encoding_schemes=list(encoding_schemes),
                encryption_patterns=encryption_patterns,
                entropy_distribution=entropy_distribution
            )
            
        except Exception as e:
            self.logger.error(f"String obfuscation analysis failed: {e}")
            return EncryptionAnalysis(0, 0, 0, [], [], {})
    
    def detect_xor_obfuscation(self) -> List[Dict[str, Any]]:
        """Detect XOR obfuscation patterns
        
        Returns:
            List of detected XOR patterns with keys and decoded content
        """
        xor_patterns = []
        
        if not self.r2:
            return xor_patterns
        
        try:
            strings = self.r2.cmdj("izj") or []
            
            for string_info in strings:
                string_data = string_info.get('string', '')
                string_addr = string_info.get('vaddr', 0)
                
                if len(string_data) < self.min_string_length:
                    continue
                
                # Test for XOR encryption
                xor_results = self._test_xor_encryption(string_data, string_addr)
                xor_patterns.extend(xor_results)
            
            return xor_patterns
            
        except Exception as e:
            self.logger.error(f"XOR obfuscation detection failed: {e}")
            return []
    
    def detect_dynamic_string_construction(self) -> List[Dict[str, Any]]:
        """Detect dynamic string construction patterns
        
        Returns:
            List of functions performing dynamic string construction
        """
        construction_patterns = []
        
        if not self.r2:
            return construction_patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze function for string construction
                pattern = self._analyze_string_construction_function(func_addr)
                if pattern:
                    construction_patterns.append(pattern)
            
            return construction_patterns
            
        except Exception as e:
            self.logger.error(f"Dynamic string construction detection failed: {e}")
            return []
    
    def detect_runtime_decryption(self) -> List[Dict[str, Any]]:
        """Detect runtime string decryption routines
        
        Returns:
            List of functions performing runtime string decryption
        """
        decryption_routines = []
        
        if not self.r2:
            return decryption_routines
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze function for decryption patterns
                routine = self._analyze_decryption_routine(func_addr)
                if routine:
                    decryption_routines.append(routine)
            
            return decryption_routines
            
        except Exception as e:
            self.logger.error(f"Runtime decryption detection failed: {e}")
            return []
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string data"""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _analyze_string_encryption(self, string_data: str, address: int, entropy: float) -> Optional[StringPattern]:
        """Analyze string for encryption patterns"""
        metadata = {'entropy': entropy}
        pattern_type = 'unknown_encryption'
        confidence = 0.5
        
        # Check for various encryption indicators
        
        # High entropy with non-printable characters
        if entropy > 7.0:
            non_printable = sum(1 for c in string_data if c not in string.printable)
            if non_printable > len(string_data) * 0.3:
                pattern_type = 'high_entropy_binary'
                confidence = 0.8
                metadata['non_printable_ratio'] = non_printable / len(string_data)
        
        # Base64-like patterns
        if self._looks_like_base64(string_data):
            pattern_type = 'base64_encoding'
            confidence = 0.7
            metadata['encoding_type'] = 'base64'
        
        # Hex encoding patterns
        elif self._looks_like_hex(string_data):
            pattern_type = 'hex_encoding'
            confidence = 0.6
            metadata['encoding_type'] = 'hexadecimal'
        
        # Custom encoding patterns
        elif self._has_custom_encoding_pattern(string_data):
            pattern_type = 'custom_encoding'
            confidence = 0.5
            metadata['encoding_type'] = 'custom'
        
        if confidence > self.encryption_confidence_threshold:
            return StringPattern(
                address=address,
                string_data=string_data,
                pattern_type=pattern_type,
                confidence=confidence,
                metadata=metadata
            )
        
        return None
    
    def _detect_encoding_scheme(self, string_data: str) -> Optional[str]:
        """Detect encoding scheme used for string"""
        # Base64 detection
        if self._looks_like_base64(string_data):
            try:
                decoded = base64.b64decode(string_data)
                if self._is_likely_text(decoded):
                    return "base64"
            except:
                pass
        
        # Hex encoding detection
        if self._looks_like_hex(string_data):
            return "hexadecimal"
        
        # URL encoding detection
        if '%' in string_data and re.search(r'%[0-9a-fA-F]{2}', string_data):
            return "url_encoding"
        
        # ROT13/Caesar cipher detection
        if self._looks_like_caesar_cipher(string_data):
            return "caesar_cipher"
        
        # Custom encoding pattern
        if self._has_custom_encoding_pattern(string_data):
            return "custom_encoding"
        
        return None
    
    def _looks_like_base64(self, data: str) -> bool:
        """Check if string looks like Base64 encoding"""
        if len(data) < 4 or len(data) % 4 != 0:
            return False
        
        # Check character set
        base64_chars = set(string.ascii_letters + string.digits + '+/=')
        return all(c in base64_chars for c in data)
    
    def _looks_like_hex(self, data: str) -> bool:
        """Check if string looks like hex encoding"""
        if len(data) < 4 or len(data) % 2 != 0:
            return False
        
        try:
            int(data, 16)
            return True
        except ValueError:
            return False
    
    def _looks_like_caesar_cipher(self, data: str) -> bool:
        """Check if string might be a Caesar cipher"""
        if not data.isalpha():
            return False
        
        # Test common Caesar shifts
        for shift in range(1, 26):
            decoded = ''.join(chr((ord(c) - ord('A') + shift) % 26 + ord('A')) 
                            if c.isupper() else 
                            chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
                            for c in data)
            
            if self._contains_common_words(decoded.lower()):
                return True
        
        return False
    
    def _contains_common_words(self, text: str) -> bool:
        """Check if text contains common English words"""
        common_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'}
        
        words = text.split()
        common_count = sum(1 for word in words if word in common_words)
        
        return common_count > len(words) * 0.3 if words else False
    
    def _has_custom_encoding_pattern(self, data: str) -> bool:
        """Check for custom encoding patterns"""
        # Look for low character diversity (substitution cipher indicator)
        unique_chars = len(set(data))
        if unique_chars < len(data) * 0.3 and len(data) > 10:
            return True
        
        # Look for repeated character patterns
        if len(data) > 8:
            for pattern_len in range(2, min(8, len(data) // 2)):
                pattern = data[:pattern_len]
                if data.count(pattern) > 3:
                    return True
        
        # Look for mathematical progressions in ASCII values
        if len(data) > 5:
            ascii_values = [ord(c) for c in data]
            differences = [ascii_values[i+1] - ascii_values[i] for i in range(len(ascii_values)-1)]
            
            # Check for constant differences (arithmetic progression)
            if len(set(differences)) == 1 and differences[0] != 0:
                return True
        
        return False
    
    def _test_xor_encryption(self, string_data: str, address: int) -> List[Dict[str, Any]]:
        """Test string for XOR encryption with common keys"""
        xor_patterns = []
        
        try:
            data_bytes = string_data.encode('latin-1')
        except:
            return xor_patterns
        
        for key in self.common_xor_keys:
            try:
                decoded = bytes(b ^ key for b in data_bytes)
                
                # Check if decoded data looks like readable text
                if self._is_likely_text(decoded):
                    confidence = self._calculate_text_likelihood(decoded)
                    
                    if confidence > 0.6:
                        xor_patterns.append({
                            'address': address,
                            'key': key,
                            'key_hex': f"0x{key:02x}",
                            'original': string_data[:50],
                            'decoded': decoded.decode('latin-1', errors='ignore')[:50],
                            'confidence': confidence,
                            'method': 'single_byte_xor'
                        })
            except:
                continue
        
        # Test multi-byte XOR keys
        multi_byte_patterns = self._test_multi_byte_xor(string_data, address)
        xor_patterns.extend(multi_byte_patterns)
        
        return xor_patterns
    
    def _is_likely_text(self, data: bytes) -> bool:
        """Check if decoded data looks like readable text"""
        try:
            text = data.decode('ascii')
            # Check for printable characters
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
            return printable_ratio > 0.7
        except:
            try:
                text = data.decode('utf-8')
                printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
                return printable_ratio > 0.7
            except:
                return False
    
    def _calculate_text_likelihood(self, data: bytes) -> float:
        """Calculate likelihood that data is readable text"""
        try:
            text = data.decode('ascii')
            
            # Count different character types
            letters = sum(1 for c in text if c.isalpha())
            digits = sum(1 for c in text if c.isdigit())
            spaces = sum(1 for c in text if c.isspace())
            printable = sum(1 for c in text if c.isprintable())
            
            total = len(text)
            if total == 0:
                return 0.0
            
            # Calculate weighted score
            score = 0.0
            score += (letters / total) * 0.5  # Letters are good
            score += (spaces / total) * 0.3   # Spaces indicate structure
            score += (digits / total) * 0.1   # Some digits are normal
            score += (printable / total) * 0.1 # All should be printable
            
            # Bonus for common words
            if self._contains_common_words(text.lower()):
                score += 0.3
            
            return min(score, 1.0)
            
        except:
            return 0.0
    
    def _test_multi_byte_xor(self, string_data: str, address: int) -> List[Dict[str, Any]]:
        """Test for multi-byte XOR encryption"""
        patterns = []
        
        try:
            data_bytes = string_data.encode('latin-1')
        except:
            return patterns
        
        # Test common multi-byte keys
        test_keys = [
            b'key', b'pass', b'xor', b'test',
            b'\x12\x34', b'\xAA\xBB', b'\x00\xFF'
        ]
        
        for key in test_keys:
            try:
                decoded = bytes(data_bytes[i] ^ key[i % len(key)] for i in range(len(data_bytes)))
                
                if self._is_likely_text(decoded):
                    confidence = self._calculate_text_likelihood(decoded)
                    
                    if confidence > 0.5:
                        patterns.append({
                            'address': address,
                            'key': key.hex(),
                            'key_length': len(key),
                            'original': string_data[:50],
                            'decoded': decoded.decode('latin-1', errors='ignore')[:50],
                            'confidence': confidence,
                            'method': 'multi_byte_xor'
                        })
            except:
                continue
        
        return patterns    def _analyze_string_construction_function(self, func_addr: int) -> Optional[Dict[str, Any]]:
        """Analyze function for dynamic string construction patterns"""
        if not self.r2:
            return None
        
        try:
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            construction_indicators = []
            confidence = 0.0
            
            # Check for string concatenation functions
            concat_functions = ['strcat', 'strncat', 'sprintf', 'snprintf', 'StringCchCat', 'StringCbCat']
            for func_name in concat_functions:
                if func_name in disasm:
                    construction_indicators.append(f'calls_{func_name}')
                    confidence += 0.3
            
            # Check for character-by-character construction
            if self._has_char_by_char_construction(disasm):
                construction_indicators.append('char_by_char_construction')
                confidence += 0.4
            
            # Check for string building loops
            if self._has_string_building_loops(disasm):
                construction_indicators.append('string_building_loops')
                confidence += 0.3
            
            # Check for memory allocation for strings
            if self._has_dynamic_string_allocation(disasm):
                construction_indicators.append('dynamic_allocation')
                confidence += 0.2
            
            if confidence > 0.5:
                return {
                    'address': func_addr,
                    'type': 'dynamic_string_construction',
                    'confidence': min(confidence, 1.0),
                    'indicators': construction_indicators,
                    'method': 'function_analysis'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"String construction analysis failed: {e}")
            return None
    
    def _has_char_by_char_construction(self, disasm: str) -> bool:
        """Check for character-by-character string construction"""
        # Look for byte operations in loops
        lines = disasm.split('\n')
        
        has_loop = any('loop' in line.lower() or ('jmp' in line.lower() and 'short' in line.lower()) 
                      for line in lines)
        has_byte_ops = any('mov byte' in line.lower() or 'stosb' in line.lower() 
                          for line in lines)
        has_increment = any('inc' in line.lower() or 'add' in line.lower() 
                           for line in lines)
        
        return has_loop and has_byte_ops and has_increment
    
    def _has_string_building_loops(self, disasm: str) -> bool:
        """Check for string building loops"""
        # Look for loops with string operations
        loop_indicators = ['loop', 'rep', 'repe', 'repne']
        string_ops = ['lods', 'stos', 'movs', 'scas']
        
        has_loop = any(indicator in disasm.lower() for indicator in loop_indicators)
        has_string_op = any(op in disasm.lower() for op in string_ops)
        
        return has_loop and has_string_op
    
    def _has_dynamic_string_allocation(self, disasm: str) -> bool:
        """Check for dynamic string memory allocation"""
        alloc_functions = ['malloc', 'calloc', 'VirtualAlloc', 'HeapAlloc', 'LocalAlloc']
        return any(func in disasm for func in alloc_functions)
    
    def _analyze_decryption_routine(self, func_addr: int) -> Optional[Dict[str, Any]]:
        """Analyze function for string decryption patterns"""
        if not self.r2:
            return None
        
        try:
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            decryption_indicators = []
            confidence = 0.0
            
            # Check for XOR operations
            if 'xor' in disasm.lower():
                decryption_indicators.append('xor_operations')
                confidence += 0.4
            
            # Check for rotation operations
            if any(op in disasm.lower() for op in ['rol', 'ror', 'shl', 'shr']):
                decryption_indicators.append('rotation_operations')
                confidence += 0.3
            
            # Check for key loading/usage
            if self._has_key_usage_pattern(disasm):
                decryption_indicators.append('key_usage')
                confidence += 0.3
            
            # Check for loop with crypto operations
            if self._has_crypto_loop(disasm):
                decryption_indicators.append('crypto_loop')
                confidence += 0.4
            
            # Check for explicit decryption calls
            decrypt_functions = ['decrypt', 'decode', 'decipher', 'unscramble']
            for func_name in decrypt_functions:
                if func_name in disasm.lower():
                    decryption_indicators.append(f'calls_{func_name}')
                    confidence += 0.5
            
            # Analyze algorithm patterns
            algorithm = self._identify_decryption_algorithm(disasm)
            if algorithm:
                decryption_indicators.append(f'algorithm_{algorithm}')
                confidence += 0.2
            
            if confidence > 0.6:
                return {
                    'address': func_addr,
                    'type': 'runtime_string_decryption',
                    'confidence': min(confidence, 1.0),
                    'indicators': decryption_indicators,
                    'algorithm': algorithm or 'unknown',
                    'method': 'function_analysis'
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Decryption routine analysis failed: {e}")
            return None
    
    def _has_key_usage_pattern(self, disasm: str) -> bool:
        """Check for cryptographic key usage patterns"""
        # Look for key-related patterns
        key_patterns = [
            'key', 'secret', 'pass', 'crypt',
            # Common key loading patterns
            'mov.*0x[0-9a-f]{8}',  # Loading constants
            'lea.*key',  # Loading key addresses
        ]
        
        return any(re.search(pattern, disasm.lower()) for pattern in key_patterns)
    
    def _has_crypto_loop(self, disasm: str) -> bool:
        """Check for cryptographic loops"""
        lines = disasm.split('\n')
        
        # Look for loops with crypto operations
        has_loop = any('loop' in line.lower() or 'jmp' in line.lower() 
                      for line in lines)
        
        crypto_ops = ['xor', 'add', 'sub', 'rol', 'ror', 'shl', 'shr']
        has_crypto = sum(1 for line in lines 
                        for op in crypto_ops 
                        if op in line.lower()) > 2
        
        return has_loop and has_crypto
    
    def _identify_decryption_algorithm(self, disasm: str) -> Optional[str]:
        """Identify the decryption algorithm being used"""
        disasm_lower = disasm.lower()
        
        # XOR-based algorithms
        if 'xor' in disasm_lower:
            if 'key' in disasm_lower or 'secret' in disasm_lower:
                return 'xor_key_based'
            else:
                return 'simple_xor'
        
        # RC4 patterns
        if ('swap' in disasm_lower or 'xchg' in disasm_lower) and 'loop' in disasm_lower:
            return 'rc4_like'
        
        # AES patterns (very simplified detection)
        if any(pattern in disasm_lower for pattern in ['aes', 'rijndael', 'subbytes']):
            return 'aes_like'
        
        # TEA/XTEA patterns
        if 'delta' in disasm_lower or ('shl' in disasm_lower and 'shr' in disasm_lower):
            return 'tea_like'
        
        # Custom algorithm with rotations
        if any(op in disasm_lower for op in ['rol', 'ror']) and 'add' in disasm_lower:
            return 'custom_rotation'
        
        return None
    
    def analyze_encoding_patterns(self) -> Dict[str, Any]:
        """Analyze various encoding patterns in strings
        
        Returns:
            Comprehensive analysis of encoding patterns
        """
        if not self.r2:
            return {'error': 'No radare2 session available'}
        
        try:
            strings = self.r2.cmdj("izj") or []
            
            encoding_stats = {
                'base64': 0,
                'hex': 0,
                'url_encoding': 0,
                'caesar_cipher': 0,
                'custom_encoding': 0,
                'unicode_escape': 0,
                'total_analyzed': 0
            }
            
            detailed_patterns = []
            
            for string_info in strings:
                string_data = string_info.get('string', '')
                string_addr = string_info.get('vaddr', 0)
                
                if len(string_data) < self.min_string_length:
                    continue
                
                encoding_stats['total_analyzed'] += 1
                
                # Test each encoding type
                if self._looks_like_base64(string_data):
                    encoding_stats['base64'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'base64',
                        'sample': string_data[:50],
                        'confidence': 0.8
                    })
                
                elif self._looks_like_hex(string_data):
                    encoding_stats['hex'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'hex',
                        'sample': string_data[:50],
                        'confidence': 0.9
                    })
                
                elif '%' in string_data and re.search(r'%[0-9a-fA-F]{2}', string_data):
                    encoding_stats['url_encoding'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'url_encoding',
                        'sample': string_data[:50],
                        'confidence': 0.7
                    })
                
                elif self._looks_like_caesar_cipher(string_data):
                    encoding_stats['caesar_cipher'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'caesar_cipher',
                        'sample': string_data[:50],
                        'confidence': 0.6
                    })
                
                elif self._has_custom_encoding_pattern(string_data):
                    encoding_stats['custom_encoding'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'custom_encoding',
                        'sample': string_data[:50],
                        'confidence': 0.5
                    })
                
                elif self._has_unicode_escape_pattern(string_data):
                    encoding_stats['unicode_escape'] += 1
                    detailed_patterns.append({
                        'address': string_addr,
                        'type': 'unicode_escape',
                        'sample': string_data[:50],
                        'confidence': 0.7
                    })
            
            # Calculate overall encoding ratio
            total_encoded = sum(encoding_stats[key] for key in encoding_stats if key != 'total_analyzed')
            encoding_ratio = total_encoded / encoding_stats['total_analyzed'] if encoding_stats['total_analyzed'] > 0 else 0
            
            return {
                'encoding_statistics': encoding_stats,
                'encoding_ratio': encoding_ratio,
                'detailed_patterns': detailed_patterns,
                'analysis_complete': True
            }
            
        except Exception as e:
            self.logger.error(f"Encoding pattern analysis failed: {e}")
            return {'error': str(e)}
    
    def _has_unicode_escape_pattern(self, data: str) -> bool:
        """Check for Unicode escape sequences"""
        unicode_patterns = [
            r'\\u[0-9a-fA-F]{4}',  # \uXXXX
            r'\\x[0-9a-fA-F]{2}',  # \xXX
            r'\\[0-7]{3}',         # \ooo (octal)
        ]
        
        return any(re.search(pattern, data) for pattern in unicode_patterns)
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics
        
        Returns:
            Statistics about string obfuscation detection
        """
        try:
            # Perform all analyses
            encryption_analysis = self.analyze_string_obfuscation()
            xor_patterns = self.detect_xor_obfuscation()
            construction_patterns = self.detect_dynamic_string_construction()
            decryption_routines = self.detect_runtime_decryption()
            encoding_analysis = self.analyze_encoding_patterns()
            
            return {
                'encryption_analysis': encryption_analysis.to_dict(),
                'xor_patterns_count': len(xor_patterns),
                'dynamic_construction_count': len(construction_patterns),
                'decryption_routines_count': len(decryption_routines),
                'encoding_analysis': encoding_analysis,
                'summary': {
                    'total_obfuscated_strings': encryption_analysis.encrypted_count,
                    'high_entropy_strings': encryption_analysis.high_entropy_count,
                    'xor_encrypted_strings': len(xor_patterns),
                    'functions_with_construction': len(construction_patterns),
                    'functions_with_decryption': len(decryption_routines),
                    'encoding_schemes_found': len(encryption_analysis.encoding_schemes),
                    'overall_obfuscation_level': self._calculate_obfuscation_level(
                        encryption_analysis, xor_patterns, construction_patterns, decryption_routines
                    )
                }
            }
            
        except Exception as e:
            self.logger.error(f"Statistics generation failed: {e}")
            return {'error': str(e)}
    
    def _calculate_obfuscation_level(self, encryption_analysis: EncryptionAnalysis, 
                                   xor_patterns: List[Dict], construction_patterns: List[Dict],
                                   decryption_routines: List[Dict]) -> str:
        """Calculate overall string obfuscation level"""
        score = 0
        
        # Weight different types of obfuscation
        if encryption_analysis.total_strings > 0:
            encrypted_ratio = encryption_analysis.encrypted_count / encryption_analysis.total_strings
            score += encrypted_ratio * 40
        
        score += len(xor_patterns) * 10
        score += len(construction_patterns) * 5
        score += len(decryption_routines) * 15
        
        if score < 10:
            return "minimal"
        elif score < 30:
            return "moderate"
        elif score < 60:
            return "high"
        else:
            return "extreme"