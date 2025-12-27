"""Comprehensive tests for semantic code analyzer.

Tests validate AST analysis, code transformation, semantic intent detection,
business pattern matching, and relationship analysis on real code samples.
"""

import ast
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.semantic_code_analyzer import (
    BusinessLogicPattern,
    IntentMismatch,
    NLPCodeProcessor,
    SemanticAnalysisResult,
    SemanticCodeAnalyzer,
    SemanticIntent,
    SemanticKnowledgeBase,
    SemanticNode,
    SemanticRelationship,
)


class TestNLPCodeProcessor:
    """Test natural language processing for code analysis."""

    def test_extract_semantic_features_authentication_code(self) -> None:
        """Validate semantic feature extraction for authentication code."""
        processor = NLPCodeProcessor()

        code = """
def authenticate_user(username: str, password: str) -> bool:
    if not username or not password:
        return False
    hashed_pass = hash_password(password)
    return verify_password(hashed_pass, username)
"""

        features = processor.extract_semantic_features(code, "authenticate_user")

        assert "vocabulary_matches" in features
        assert features["vocabulary_matches"]["authentication"] > 0
        assert "intent_scores" in features
        assert features["intent_scores"]["authentication"] > 0
        assert len(features["semantic_tokens"]) > 0
        assert "authenticate" in features["semantic_tokens"] or "auth" in features["semantic_tokens"]

    def test_extract_semantic_features_license_validation(self) -> None:
        """Validate semantic feature extraction for license validation code."""
        processor = NLPCodeProcessor()

        code = """
def validate_license_key(license_key: str) -> bool:
    if not license_key or len(license_key) < 16:
        return False
    if check_expiry_date(license_key):
        return is_valid_registration(license_key)
    return False
"""

        features = processor.extract_semantic_features(code, "validate_license_key")

        assert features["vocabulary_matches"]["license"] > 0
        assert features["business_scores"]["license_validation"] > 0
        assert "validation" in features["intent_scores"]
        assert features["complexity_indicators"]["conditional_statements"] >= 2

    def test_extract_complexity_indicators_nested_code(self) -> None:
        """Test complexity indicator extraction for nested control structures."""
        processor = NLPCodeProcessor()

        code = """
def complex_function(data):
    for item in data:
        if item.valid:
            while item.process():
                try:
                    result = calculate(item)
                    if result > 0:
                        return result
                except Exception as e:
                    handle_error(e)
    return None
"""

        features = processor.extract_semantic_features(code)
        indicators = features["complexity_indicators"]

        assert indicators["conditional_statements"] >= 2
        assert indicators["loop_statements"] >= 2
        assert indicators["exception_handling"] >= 2
        assert indicators["nested_blocks"] > 3

    def test_normalize_code_removes_comments(self) -> None:
        """Test code normalization removes comments correctly."""
        processor = NLPCodeProcessor()

        code = """
# This is a comment
def func():  # inline comment
    pass
"""

        normalized = processor._normalize_code(code)

        assert "#" not in normalized
        assert "comment" not in normalized

    def test_split_camel_case_handles_multiple_formats(self) -> None:
        """Test camelCase and snake_case splitting."""
        processor = NLPCodeProcessor()

        assert "validate" in processor._split_camel_case("validateLicense")
        assert "license" in processor._split_camel_case("validateLicense")
        assert "user" in processor._split_camel_case("user_name")
        assert "name" in processor._split_camel_case("user_name")
        assert len(processor._split_camel_case("HTTPSConnection")) > 1


class TestSemanticCodeAnalyzer:
    """Test deep semantic code analysis system."""

    def test_analyze_file_python_authentication_code(self) -> None:
        """Test semantic analysis of real Python authentication code."""
        analyzer = SemanticCodeAnalyzer()

        code = """
import hashlib
import secrets

def authenticate_user(username: str, password: str) -> bool:
    if not username or not password:
        return False

    stored_hash = get_user_password_hash(username)
    if not stored_hash:
        return False

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    return secrets.compare_digest(password_hash, stored_hash)

def get_user_password_hash(username: str) -> str:
    return database.query(f"SELECT password FROM users WHERE name = '{username}'")
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert isinstance(result, SemanticAnalysisResult)
            assert len(result.semantic_nodes) >= 2
            assert result.confidence > 0.0

            node_names = [node.name for node in result.semantic_nodes]
            assert "authenticate_user" in node_names
            assert "get_user_password_hash" in node_names

            auth_node = next(n for n in result.semantic_nodes if n.name == "authenticate_user")
            assert auth_node.semantic_intent == SemanticIntent.AUTHENTICATION

        finally:
            Path(temp_path).unlink()

    def test_analyze_file_license_validation_with_mismatches(self) -> None:
        """Test detection of intent mismatches in license validation code."""
        analyzer = SemanticCodeAnalyzer()

        code = """
def validate_license(key: str) -> bool:
    return True

def check_license_expiry(key: str) -> bool:
    pass
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert len(result.semantic_nodes) >= 2
            assert len(result.intent_mismatches) > 0

            mismatch = result.intent_mismatches[0]
            assert mismatch.mismatch_type in ["insufficient_validation", "trivial_validation"]
            assert len(mismatch.suggested_fixes) > 0

        finally:
            Path(temp_path).unlink()

    def test_analyze_javascript_frida_script(self) -> None:
        """Test semantic analysis of JavaScript (Frida) code."""
        analyzer = SemanticCodeAnalyzer()

        code = """
Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function(args) {
        console.log('Opening file: ' + Memory.readUtf8String(args[0]));
    },
    onLeave: function(retval) {
        console.log('File descriptor: ' + retval);
    }
});

function hookCryptoFunctions() {
    var encryptPtr = Module.findExportByName('libcrypto.so', 'EVP_EncryptInit');
    Interceptor.attach(encryptPtr, {
        onEnter: function(args) {
            send({type: 'crypto', operation: 'encrypt'});
        }
    });
}
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert isinstance(result, SemanticAnalysisResult)
            assert len(result.semantic_nodes) > 0

            function_nodes = [n for n in result.semantic_nodes if n.node_type == "Function"]
            assert len(function_nodes) > 0

        finally:
            Path(temp_path).unlink()

    def test_analyze_relationships_function_calls(self) -> None:
        """Test relationship detection between functions with calls."""
        analyzer = SemanticCodeAnalyzer()

        code = """
def validate_input(data):
    return sanitize_data(data)

def sanitize_data(data):
    return data.strip().lower()

def process_request(request):
    data = validate_input(request.data)
    return data
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert len(result.relationships) > 0

            call_relationships = [r for r in result.relationships if r.relationship_type == "calls"]
            assert len(call_relationships) > 0

            rel = call_relationships[0]
            assert rel.confidence > 0.5
            assert rel.strength > 0.5

        finally:
            Path(temp_path).unlink()

    def test_calculate_complexity_metrics_high_complexity(self) -> None:
        """Test complexity metric calculation for high-complexity code."""
        analyzer = SemanticCodeAnalyzer()

        code = """
def complex_license_check(key, user, product):
    if not key:
        return False

    if not validate_format(key):
        return False

    if not check_user_access(user):
        return False

    if not verify_product_license(product):
        return False

    for module in get_modules():
        if not check_module_license(module, key):
            return False

    return True

def validate_format(key):
    pass

def check_user_access(user):
    pass

def verify_product_license(product):
    pass

def get_modules():
    pass

def check_module_license(module, key):
    pass
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            metrics = result.complexity_metrics
            assert metrics["function_count"] >= 5
            assert metrics["semantic_complexity"] >= 5
            assert metrics["intent_diversity"] > 0

            summary = result.semantic_summary
            assert summary["complexity_level"] in ["low", "medium", "high"]

        finally:
            Path(temp_path).unlink()

    def test_detect_weak_authentication_patterns(self) -> None:
        """Test detection of weak authentication implementation."""
        analyzer = SemanticCodeAnalyzer()

        code = """
def authenticate(username, password):
    if password == "admin123":
        return True
    return False

def login_user(username, password):
    if password:
        return True
    return False
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            mismatches = result.intent_mismatches
            auth_mismatches = [m for m in mismatches if m.expected_intent == SemanticIntent.AUTHENTICATION]

            assert len(auth_mismatches) > 0
            mismatch = auth_mismatches[0]
            assert mismatch.severity in ["high", "medium"]
            assert "weak_patterns" in mismatch.evidence or len(mismatch.suggested_fixes) > 0

        finally:
            Path(temp_path).unlink()

    def test_business_logic_mapping_license_patterns(self) -> None:
        """Test business logic pattern identification in license code."""
        analyzer = SemanticCodeAnalyzer()

        code = """
def check_trial_expiry(license_key):
    expiry_date = extract_expiry(license_key)
    return expiry_date > current_date()

def activate_license(activation_code):
    if verify_activation(activation_code):
        return generate_license_key()
    return None

def validate_serial_number(serial):
    return check_serial_format(serial) and verify_checksum(serial)
"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            business_map = result.business_logic_map

            license_nodes = [
                node_id for node_id, pattern in business_map.items()
                if pattern == BusinessLogicPattern.LICENSE_VALIDATION
            ]

            assert len(license_nodes) > 0

        finally:
            Path(temp_path).unlink()

    def test_cache_functionality_repeated_analysis(self) -> None:
        """Test that analysis caching works for repeated file analysis."""
        analyzer = SemanticCodeAnalyzer()

        code = "def test_func():\n    pass"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result1 = analyzer.analyze_file(temp_path)
            result2 = analyzer.analyze_file(temp_path)

            assert result1.analysis_id == result2.analysis_id
            assert result1.confidence == result2.confidence

        finally:
            Path(temp_path).unlink()

    def test_get_semantic_insights_multiple_files(self) -> None:
        """Test semantic insights aggregation across multiple files."""
        analyzer = SemanticCodeAnalyzer()

        files = []

        try:
            for i, code in enumerate([
                "def authenticate(u, p):\n    return verify(u, p)",
                "def validate_license(k):\n    return check(k)",
                "def encrypt_data(d):\n    return hash(d)"
            ]):
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                    f.write(code)
                    files.append(f.name)

            insights = analyzer.get_semantic_insights(files)

            assert insights["files_analyzed"] == 3
            assert insights["total_nodes"] > 0
            assert "intent_distribution" in insights
            assert "complexity_overview" in insights
            assert insights["avg_confidence"] > 0.0

        finally:
            for file_path in files:
                Path(file_path).unlink()


class TestSemanticNode:
    """Test semantic node creation and properties."""

    def test_semantic_node_creation_with_all_fields(self) -> None:
        """Test creating semantic node with complete data."""
        node = SemanticNode(
            node_id="test_node_1",
            node_type="FunctionDef",
            name="test_function",
            semantic_intent=SemanticIntent.VALIDATION,
            business_pattern=BusinessLogicPattern.DATA_VALIDATION,
            confidence=0.85,
            location={"line": 10, "column": 4},
            content="def test_function():\n    pass",
            dependencies=["dep1", "dep2"],
            metadata={"author": "test"},
            nlp_features={"tokens": ["test", "function"]}
        )

        assert node.node_id == "test_node_1"
        assert node.semantic_intent == SemanticIntent.VALIDATION
        assert node.business_pattern == BusinessLogicPattern.DATA_VALIDATION
        assert node.confidence == 0.85
        assert len(node.dependencies) == 2


class TestSemanticRelationship:
    """Test semantic relationship modeling."""

    def test_relationship_creation_calls_type(self) -> None:
        """Test creating function call relationship."""
        rel = SemanticRelationship(
            relationship_id="rel_1",
            source_node="func_a",
            target_node="func_b",
            relationship_type="calls",
            strength=0.9,
            confidence=0.95,
            description="func_a calls func_b"
        )

        assert rel.relationship_type == "calls"
        assert rel.strength == 0.9
        assert rel.confidence == 0.95


class TestIntentMismatch:
    """Test intent mismatch detection."""

    def test_mismatch_creation_with_fixes(self) -> None:
        """Test creating mismatch with suggested fixes."""
        mismatch = IntentMismatch(
            mismatch_id="mismatch_1",
            function_name="validate_input",
            expected_intent=SemanticIntent.VALIDATION,
            actual_implementation="trivial_validation",
            mismatch_type="insufficient_validation",
            severity="high",
            confidence=0.9,
            suggested_fixes=["Add null check", "Add type validation"],
            evidence={"patterns": ["return True"]}
        )

        assert mismatch.severity == "high"
        assert len(mismatch.suggested_fixes) == 2
        assert "patterns" in mismatch.evidence


class TestSemanticKnowledgeBase:
    """Test semantic knowledge base for patterns and rules."""

    def test_knowledge_base_initialization(self) -> None:
        """Test knowledge base initializes with patterns."""
        kb = SemanticKnowledgeBase()

        assert len(kb.patterns) > 0
        assert len(kb.anti_patterns) > 0
        assert "security_validation" in kb.patterns
        assert "weak_validation" in kb.anti_patterns

    def test_security_patterns_defined(self) -> None:
        """Test security validation patterns are defined."""
        kb = SemanticKnowledgeBase()

        security_pattern = kb.patterns["security_validation"]
        assert "indicators" in security_pattern
        assert "required_checks" in security_pattern
        assert isinstance(security_pattern["confidence_boost"], float)

    def test_anti_patterns_for_hardcoded_credentials(self) -> None:
        """Test anti-pattern detection for hardcoded credentials."""
        kb = SemanticKnowledgeBase()

        anti_pattern = kb.anti_patterns["hardcoded_credentials"]
        assert anti_pattern["severity"] == "high"
        assert "indicators" in anti_pattern
        assert isinstance(anti_pattern["confidence_penalty"], float)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_empty_file(self) -> None:
        """Test analysis of empty file."""
        analyzer = SemanticCodeAnalyzer()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("")
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert isinstance(result, SemanticAnalysisResult)
            assert len(result.semantic_nodes) == 0

        finally:
            Path(temp_path).unlink()

    def test_analyze_syntax_error_file(self) -> None:
        """Test analysis of file with syntax errors."""
        analyzer = SemanticCodeAnalyzer()

        code = "def broken(\n    incomplete"

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert isinstance(result, SemanticAnalysisResult)

        finally:
            Path(temp_path).unlink()

    def test_analyze_nonexistent_file(self) -> None:
        """Test analysis of nonexistent file."""
        analyzer = SemanticCodeAnalyzer()

        result = analyzer.analyze_file("/nonexistent/path/file.py")

        assert isinstance(result, SemanticAnalysisResult)
        assert result.confidence == 0.0

    def test_analyze_binary_file(self) -> None:
        """Test analysis of binary file returns gracefully."""
        analyzer = SemanticCodeAnalyzer()

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
            temp_path = f.name

        try:
            result = analyzer.analyze_file(temp_path)

            assert isinstance(result, SemanticAnalysisResult)

        finally:
            Path(temp_path).unlink()

    def test_extract_features_very_long_code(self) -> None:
        """Test feature extraction on very long code."""
        processor = NLPCodeProcessor()

        code = "\n".join([f"def func_{i}():\n    pass" for i in range(100)])

        features = processor.extract_semantic_features(code)

        assert "vocabulary_matches" in features
        assert "complexity_indicators" in features

    def test_analyze_deeply_nested_code(self) -> None:
        """Test analysis of deeply nested code structures."""
        processor = NLPCodeProcessor()

        code = """
def outer():
    def middle():
        def inner():
            def deep():
                if True:
                    while True:
                        for i in range(10):
                            try:
                                pass
                            except:
                                pass
"""

        features = processor.extract_semantic_features(code)

        assert features["complexity_indicators"]["nested_blocks"] > 5
