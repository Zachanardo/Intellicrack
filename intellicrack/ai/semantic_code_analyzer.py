"""Semantic Code Understanding System.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import ast
import hashlib
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger
from .learning_engine_simple import get_learning_engine
from .llm_backends import LLMManager
from .performance_monitor import profile_ai_operation

logger = get_logger(__name__)


class SemanticIntent(Enum):
    """Types of semantic intent in code."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    ENCRYPTION = "encryption"
    COMMUNICATION = "communication"
    DATA_PROCESSING = "data_processing"
    ERROR_HANDLING = "error_handling"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    BUSINESS_LOGIC = "business_logic"
    SECURITY_CHECK = "security_check"
    RESOURCE_MANAGEMENT = "resource_management"
    USER_INTERFACE = "user_interface"
    DATABASE_OPERATION = "database_operation"
    FILE_OPERATION = "file_operation"
    NETWORK_OPERATION = "network_operation"


class BusinessLogicPattern(Enum):
    """Provide business logic patterns."""

    LICENSE_VALIDATION = "license_validation"
    USER_MANAGEMENT = "user_management"
    PAYMENT_PROCESSING = "payment_processing"
    ACCESS_CONTROL = "access_control"
    DATA_VALIDATION = "data_validation"
    WORKFLOW_MANAGEMENT = "workflow_management"
    AUDIT_LOGGING = "audit_logging"
    CONFIGURATION_MANAGEMENT = "configuration_management"
    FEATURE_FLAGS = "feature_flags"
    RATE_LIMITING = "rate_limiting"


@dataclass
class SemanticNode:
    """Semantic node representing code element."""

    node_id: str
    node_type: str
    name: str
    semantic_intent: SemanticIntent
    business_pattern: BusinessLogicPattern | None
    confidence: float
    location: dict[str, int]  # line, column info
    content: str
    dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    nlp_features: dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticRelationship:
    """Relationship between semantic nodes."""

    relationship_id: str
    source_node: str
    target_node: str
    relationship_type: str
    strength: float
    confidence: float
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IntentMismatch:
    """Detected mismatch between intent and implementation."""

    mismatch_id: str
    function_name: str
    expected_intent: SemanticIntent
    actual_implementation: str
    mismatch_type: str
    severity: str
    confidence: float
    suggested_fixes: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticAnalysisResult:
    """Result of semantic code analysis."""

    analysis_id: str
    file_path: str
    semantic_nodes: list[SemanticNode]
    relationships: list[SemanticRelationship]
    intent_mismatches: list[IntentMismatch]
    business_logic_map: dict[str, BusinessLogicPattern]
    complexity_metrics: dict[str, float]
    semantic_summary: dict[str, Any]
    confidence: float
    analysis_time: float


class NLPCodeProcessor:
    """Natural Language Processing for code analysis."""

    def __init__(self) -> None:
        """Initialize the NLP code processor.

        Sets up vocabulary, semantic patterns, intent keywords,
        and business keywords for natural language processing
        of code analysis tasks.
        """
        self.vocabulary = self._build_code_vocabulary()
        self.semantic_patterns = self._load_semantic_patterns()
        self.intent_keywords = self._load_intent_keywords()
        self.business_keywords = self._load_business_keywords()

        logger.info("NLP code processor initialized")

    def _build_code_vocabulary(self) -> dict[str, list[str]]:
        """Build vocabulary for code analysis."""
        return {
            "authentication": [
                "login",
                "signin",
                "authenticate",
                "verify",
                "credential",
                "password",
                "token",
                "session",
                "auth",
                "validate_user",
                "check_password",
            ],
            "authorization": [
                "authorize",
                "permission",
                "access",
                "role",
                "privilege",
                "allow",
                "deny",
                "grant",
                "revoke",
                "check_access",
                "has_permission",
            ],
            "validation": [
                "validate",
                "verify",
                "check",
                "sanitize",
                "filter",
                "clean",
                "ensure",
                "confirm",
                "assert",
                "is_valid",
                "meets_criteria",
            ],
            "encryption": [
                "encrypt",
                "decrypt",
                "hash",
                "cipher",
                "crypto",
                "encode",
                "decode",
                "scramble",
                "secure",
                "protect",
                "obfuscate",
            ],
            "communication": [
                "send",
                "receive",
                "transmit",
                "broadcast",
                "message",
                "signal",
                "notify",
                "alert",
                "communicate",
                "exchange",
                "transfer",
            ],
            "security": [
                "secure",
                "protect",
                "defend",
                "guard",
                "shield",
                "safe",
                "security",
                "vulnerability",
                "threat",
                "attack",
                "exploit",
            ],
            "license": [
                "license",
                "key",
                "activation",
                "registration",
                "trial",
                "expire",
                "valid",
                "invalid",
                "check",
                "verify",
            ],
            "error_handling": [
                "error",
                "exception",
                "catch",
                "handle",
                "try",
                "finally",
                "throw",
                "raise",
                "fail",
                "abort",
                "recover",
            ],
        }

    def _load_semantic_patterns(self) -> dict[str, list[str]]:
        """Load semantic patterns for intent recognition."""
        return {
            "validation_pattern": [
                r"if\s+not\s+\w+",
                r"if\s+\w+\s+is\s+None",
                r"if\s+len\(\w+\)\s*[<>]=?\s*\d+",
                r"if\s+\w+\.startswith\(",
                r"if\s+\w+\.endswith\(",
                r"if\s+re\.match\(",
            ],
            "authentication_pattern": [
                r"password\s*==\s*",
                r"check.*password",
                r"verify.*user",
                r"authenticate.*",
                r"login.*check",
                r"session.*valid",
            ],
            "license_pattern": [
                r"license.*valid",
                r"key.*check",
                r"trial.*expire",
                r"activation.*code",
                r"registration.*verify",
            ],
            "security_pattern": [
                r"access.*control",
                r"permission.*check",
                r"role.*verify",
                r"security.*validation",
                r"threat.*detection",
            ],
        }

    def _load_intent_keywords(self) -> dict[SemanticIntent, list[str]]:
        """Load keywords for intent classification."""
        return {
            SemanticIntent.AUTHENTICATION: [
                "authenticate",
                "login",
                "signin",
                "password",
                "credential",
                "verify_user",
                "check_login",
                "validate_password",
            ],
            SemanticIntent.AUTHORIZATION: [
                "authorize",
                "permission",
                "access_control",
                "role_check",
                "privilege",
                "grant",
                "deny",
                "allow",
            ],
            SemanticIntent.VALIDATION: [
                "validate",
                "verify",
                "check",
                "sanitize",
                "filter",
                "ensure",
                "confirm",
                "is_valid",
            ],
            SemanticIntent.ENCRYPTION: [
                "encrypt",
                "decrypt",
                "hash",
                "cipher",
                "crypto",
                "encode",
                "decode",
                "secure",
            ],
            SemanticIntent.BUSINESS_LOGIC: [
                "calculate",
                "process",
                "compute",
                "determine",
                "evaluate",
                "assess",
                "analyze",
                "transform",
            ],
            SemanticIntent.SECURITY_CHECK: [
                "security",
                "protect",
                "defend",
                "guard",
                "shield",
                "vulnerability",
                "threat",
                "attack",
            ],
        }

    def _load_business_keywords(self) -> dict[BusinessLogicPattern, list[str]]:
        """Load keywords for business logic pattern recognition."""
        return {
            BusinessLogicPattern.LICENSE_VALIDATION: [
                "license",
                "key",
                "activation",
                "trial",
                "expire",
                "valid",
                "registration",
                "serial",
            ],
            BusinessLogicPattern.USER_MANAGEMENT: [
                "user",
                "account",
                "profile",
                "create_user",
                "delete_user",
                "update_user",
                "manage",
            ],
            BusinessLogicPattern.ACCESS_CONTROL: [
                "access",
                "permission",
                "role",
                "privilege",
                "acl",
                "authorization",
                "grant",
                "deny",
            ],
            BusinessLogicPattern.DATA_VALIDATION: [
                "validate",
                "verify",
                "check",
                "sanitize",
                "clean",
                "format",
                "constraint",
            ],
            BusinessLogicPattern.AUDIT_LOGGING: [
                "audit",
                "log",
                "track",
                "record",
                "monitor",
                "trace",
                "history",
            ],
        }

    def extract_semantic_features(self, code: str, function_name: str = "") -> dict[str, Any]:
        """Extract semantic features from code."""
        features = {
            "vocabulary_matches": {},
            "pattern_matches": {},
            "intent_scores": {},
            "business_scores": {},
            "complexity_indicators": {},
            "semantic_tokens": [],
        }

        # Normalize code for analysis
        normalized_code = self._normalize_code(code)

        # Extract vocabulary matches
        for category, keywords in self.vocabulary.items():
            matches = sum(1 for keyword in keywords if keyword.lower() in normalized_code.lower())
            features["vocabulary_matches"][category] = matches

        # Extract pattern matches
        for pattern_name, patterns in self.semantic_patterns.items():
            matches = 0
            for pattern in patterns:
                matches += len(re.findall(pattern, code, re.IGNORECASE))
            features["pattern_matches"][pattern_name] = matches

        # Calculate intent scores
        for intent, keywords in self.intent_keywords.items():
            score = sum(1 for keyword in keywords if keyword.lower() in normalized_code.lower())
            features["intent_scores"][intent.value] = score

        # Calculate business pattern scores
        for pattern, keywords in self.business_keywords.items():
            score = sum(1 for keyword in keywords if keyword.lower() in normalized_code.lower())
            features["business_scores"][pattern.value] = score

        # Extract complexity indicators
        features["complexity_indicators"] = self._extract_complexity_indicators(code)

        # Extract semantic tokens
        features["semantic_tokens"] = self._extract_semantic_tokens(code, function_name)

        return features

    def _normalize_code(self, code: str) -> str:
        """Normalize code for analysis."""
        # Remove comments
        code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)

        # Normalize whitespace
        code = re.sub(r"\s+", " ", code)

        # Convert to lowercase for keyword matching
        return code.strip()

    def _extract_complexity_indicators(self, code: str) -> dict[str, int]:
        """Extract complexity indicators from code."""
        indicators = {
            "conditional_statements": len(re.findall(r"\bif\b", code, re.IGNORECASE)),
            "loop_statements": len(re.findall(r"\b(for|while)\b", code, re.IGNORECASE)),
            "function_calls": len(re.findall(r"\w+\s*\(", code)),
            "return_statements": len(re.findall(r"\breturn\b", code, re.IGNORECASE)),
            "exception_handling": len(re.findall(r"\b(try|catch|except|finally)\b", code, re.IGNORECASE)),
            "nested_blocks": self._count_nested_blocks(code),
        }

        return indicators

    def _count_nested_blocks(self, code: str) -> int:
        """Count nested blocks in code."""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char in {"{", "("}:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in {"}", ")"}:
                current_depth = max(0, current_depth - 1)

        return max_depth

    def _extract_semantic_tokens(self, code: str, function_name: str) -> list[str]:
        """Extract meaningful semantic tokens."""
        tokens = []

        # Add function name components
        if function_name:
            tokens.extend(self._split_camel_case(function_name))

        # Extract meaningful identifiers
        identifiers = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", code)
        for identifier in identifiers:
            if len(identifier) > 2 and not identifier.isupper():  # Skip constants
                tokens.extend(self._split_camel_case(identifier))

        # Filter common words
        meaningful_tokens = [
            token.lower()
            for token in tokens
            if len(token) > 2
            and token.lower()
            not in {
                "the",
                "and",
                "for",
                "get",
                "set",
                "new",
                "old",
                "tmp",
                "temp",
            }
        ]

        return list(set(meaningful_tokens))

    def _split_camel_case(self, text: str) -> list[str]:
        """Split camelCase or ``snake_case`` text into words."""
        # Handle camelCase
        camel_split = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).split()

        # Handle snake_case
        result = []
        for word in camel_split:
            result.extend(word.split("_"))

        return [w for w in result if w]


class SemanticCodeAnalyzer:
    """Deep semantic code analysis system."""

    def __init__(self, llm_manager: LLMManager | None = None) -> None:
        """Initialize the semantic code analyzer.

        Args:
            llm_manager: Optional language model manager instance.
                If not provided, creates a new instance.

        """
        self.logger = logging.getLogger(__name__ + ".SemanticCodeAnalyzer")
        self.llm_manager = llm_manager or LLMManager()
        self.nlp_processor = NLPCodeProcessor()

        # Analysis cache
        self.analysis_cache: dict[str, SemanticAnalysisResult] = {}
        self.cache_ttl = 3600  # 1 hour

        # Semantic knowledge base
        self.semantic_kb = SemanticKnowledgeBase()

        logger.info("Semantic code analyzer initialized")

    @profile_ai_operation("semantic_code_analysis")
    def analyze_file(self, file_path: str, content: str | None = None) -> SemanticAnalysisResult:
        """Perform semantic analysis of a code file."""
        start_time = datetime.now()

        # Check cache
        file_hash = self._calculate_file_hash(file_path, content)
        if file_hash in self.analysis_cache:
            cached_result = self.analysis_cache[file_hash]
            if (datetime.now() - start_time).total_seconds() < self.cache_ttl:
                return cached_result

        # Read content if not provided
        if content is None:
            # Try to use AIFileTools for file reading if available
            try:
                from .ai_file_tools import get_ai_file_tools

                ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
                file_data = ai_file_tools.read_file(file_path, purpose="Semantic code analysis for protection patterns")
                if file_data.get("status") == "success" and file_data.get("content"):
                    content = file_data["content"]
                else:
                    # Fallback to direct file reading
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
            except (ImportError, AttributeError, KeyError):
                # AIFileTools not available, use direct file reading
                try:
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
                except Exception as e:
                    logger.error(f"Failed to read file {file_path}: {e}")
                    return self._create_empty_result(file_path)
            except Exception as e:
                logger.error(f"Failed to read file {file_path}: {e}")
                return self._create_empty_result(file_path)

        # Perform analysis
        try:
            analysis_result = self._perform_semantic_analysis(file_path, content)
            analysis_result.analysis_time = (datetime.now() - start_time).total_seconds()

            # Cache result
            self.analysis_cache[file_hash] = analysis_result

            # Record learning experience
            get_learning_engine().record_experience(
                task_type="semantic_code_analysis",
                input_data={"file_path": file_path, "content_length": len(content)},
                output_data={
                    "nodes_found": len(analysis_result.semantic_nodes),
                    "relationships_found": len(analysis_result.relationships),
                    "mismatches_found": len(analysis_result.intent_mismatches),
                },
                success=True,
                confidence=analysis_result.confidence,
                execution_time=analysis_result.analysis_time,
                memory_usage=0,
                context={"analyzer": "semantic", "file_type": Path(file_path).suffix},
            )

            return analysis_result

        except Exception as e:
            logger.error(f"Semantic analysis failed for {file_path}: {e}")

            # Record learning experience for failure
            get_learning_engine().record_experience(
                task_type="semantic_code_analysis",
                input_data={"file_path": file_path},
                output_data={},
                success=False,
                confidence=0.0,
                execution_time=(datetime.now() - start_time).total_seconds(),
                memory_usage=0,
                error_message=str(e),
                context={"analyzer": "semantic", "file_type": Path(file_path).suffix},
            )

            return self._create_empty_result(file_path)

    def _perform_semantic_analysis(self, file_path: str, content: str) -> SemanticAnalysisResult:
        """Perform the actual semantic analysis."""
        analysis_id = f"semantic_{hashlib.md5(f'{file_path}{datetime.now()}'.encode(), usedforsecurity=False).hexdigest()[:8]}"

        # Parse code structure
        ast_nodes = self._parse_code_structure(content, file_path)

        # Extract semantic nodes
        semantic_nodes = []
        for ast_node in ast_nodes:
            semantic_node = self._create_semantic_node(ast_node, content)
            if semantic_node:
                semantic_nodes.append(semantic_node)

        # Analyze relationships
        relationships = self._analyze_relationships(semantic_nodes)

        # Detect intent mismatches
        intent_mismatches = self._detect_intent_mismatches(semantic_nodes, content)

        # Map business logic patterns
        business_logic_map = self._map_business_logic(semantic_nodes)

        # Calculate complexity metrics
        complexity_metrics = self._calculate_complexity_metrics(semantic_nodes, content)

        # Generate semantic summary
        semantic_summary = self._generate_semantic_summary(semantic_nodes, relationships)

        # Calculate overall confidence
        confidence = self._calculate_analysis_confidence(semantic_nodes, relationships)

        return SemanticAnalysisResult(
            analysis_id=analysis_id,
            file_path=file_path,
            semantic_nodes=semantic_nodes,
            relationships=relationships,
            intent_mismatches=intent_mismatches,
            business_logic_map=business_logic_map,
            complexity_metrics=complexity_metrics,
            semantic_summary=semantic_summary,
            confidence=confidence,
            analysis_time=0.0,  # Will be set by caller
        )

    def _parse_code_structure(self, content: str, file_path: str) -> list[dict[str, Any]]:
        """Parse code structure using AST."""
        ast_nodes = []

        try:
            if file_path.endswith(".py"):
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                        ast_nodes.append(
                            {
                                "type": type(node).__name__,
                                "name": node.name,
                                "line": node.lineno,
                                "col": node.col_offset,
                                "content": self._extract_node_content(content, node),
                                "docstring": ast.get_docstring(node),
                                "node": node,
                            },
                        )

            else:
                # For non-Python files, use regex-based parsing
                ast_nodes.extend(self._parse_non_python_structure(content, file_path))

        except Exception as e:
            logger.warning(f"Failed to parse AST for {file_path}: {e}")
            # Fallback to regex-based parsing
            ast_nodes.extend(self._parse_non_python_structure(content, file_path))

        return ast_nodes

    def _parse_non_python_structure(self, content: str, file_path: str) -> list[dict[str, Any]]:
        """Parse non-Python code structure using regex."""
        ast_nodes = []

        # JavaScript/TypeScript function patterns
        if file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            # Function declarations
            function_pattern = r"function\s+(\w+)\s*\([^)]*\)\s*\{"
            for match in re.finditer(function_pattern, content):
                ast_nodes.append(
                    {
                        "type": "Function",
                        "name": match.group(1),
                        "line": content[: match.start()].count("\n") + 1,
                        "col": match.start() - content.rfind("\n", 0, match.start()),
                        "content": self._extract_function_body(content, match.start()),
                        "docstring": None,
                    },
                )

            # Class declarations
            class_pattern = r"class\s+(\w+)(?:\s+extends\s+\w+)?\s*\{"
            for match in re.finditer(class_pattern, content):
                ast_nodes.append(
                    {
                        "type": "Class",
                        "name": match.group(1),
                        "line": content[: match.start()].count("\n") + 1,
                        "col": match.start() - content.rfind("\n", 0, match.start()),
                        "content": self._extract_class_body(content, match.start()),
                        "docstring": None,
                    },
                )

        # C/C++ function patterns
        elif file_path.endswith((".c", ".cpp", ".h", ".hpp")):
            # Function definitions
            func_pattern = r"(?:[\w\s\*]+\s+)?(\w+)\s*\([^)]*\)\s*\{"
            for match in re.finditer(func_pattern, content):
                ast_nodes.append(
                    {
                        "type": "Function",
                        "name": match.group(1),
                        "line": content[: match.start()].count("\n") + 1,
                        "col": match.start() - content.rfind("\n", 0, match.start()),
                        "content": self._extract_function_body(content, match.start()),
                        "docstring": None,
                    },
                )

        return ast_nodes

    def _extract_node_content(self, content: str, node: ast.AST) -> str:
        """Extract content for AST node."""
        lines = content.split("\n")

        if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
            start_line = node.lineno - 1
            end_line = node.end_lineno if node.end_lineno else start_line + 1
            return "\n".join(lines[start_line:end_line])

        return ""

    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body from position."""
        brace_count = 0
        in_function = False
        end_pos = start_pos

        for i, char in enumerate(content[start_pos:]):
            if char == "{":
                brace_count += 1
                in_function = True
            elif char == "}":
                brace_count -= 1
                if in_function and brace_count == 0:
                    end_pos = start_pos + i + 1
                    break

        return content[start_pos:end_pos]

    def _extract_class_body(self, content: str, start_pos: int) -> str:
        """Extract class body from position."""
        return self._extract_function_body(content, start_pos)  # Same logic

    def _create_semantic_node(self, ast_node: dict[str, Any], content: str) -> SemanticNode | None:
        """Create semantic node from AST node."""
        try:
            node_content = ast_node.get("content", "") or content
            node_name = ast_node.get("name", "")

            # Extract NLP features
            nlp_features = self.nlp_processor.extract_semantic_features(node_content, node_name)

            # Determine semantic intent
            semantic_intent = self._determine_semantic_intent(nlp_features, node_name, node_content)

            # Determine business pattern
            business_pattern = self._determine_business_pattern(nlp_features, node_name, node_content)

            # Calculate confidence
            confidence = self._calculate_node_confidence(nlp_features, semantic_intent)

            node_id = f"{ast_node.get('type', 'unknown')}_{node_name}_{ast_node.get('line', 0)}"

            return SemanticNode(
                node_id=node_id,
                node_type=ast_node.get("type", "unknown"),
                name=node_name,
                semantic_intent=semantic_intent,
                business_pattern=business_pattern,
                confidence=confidence,
                location={
                    "line": ast_node.get("line", 0),
                    "column": ast_node.get("col", 0),
                },
                content=node_content,
                nlp_features=nlp_features,
                metadata={
                    "docstring": ast_node.get("docstring"),
                    "complexity": nlp_features.get("complexity_indicators", {}),
                },
            )

        except Exception as e:
            logger.error(f"Failed to create semantic node: {e}")
            return None

    def _determine_semantic_intent(self, nlp_features: dict[str, Any], node_name: str, content: str) -> SemanticIntent:
        """Determine semantic intent of code node."""
        intent_scores = nlp_features.get("intent_scores", {})

        # Find highest scoring intent
        if intent_scores:
            max_intent = max(intent_scores.items(), key=lambda x: x[1])
            if max_intent[1] > 0:
                try:
                    return SemanticIntent(max_intent[0])
                except ValueError as e:
                    self.logger.error("Value error in semantic_code_analyzer: %s", e)

        # Fallback to name and content-based analysis
        node_name_lower = node_name.lower()
        content_lower = content.lower()

        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["auth", "login", "signin", "verify"]):
            return SemanticIntent.AUTHENTICATION
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["validate", "check", "verify"]):
            return SemanticIntent.VALIDATION
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["encrypt", "decrypt", "hash"]):
            return SemanticIntent.ENCRYPTION
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["send", "receive", "connect"]):
            return SemanticIntent.COMMUNICATION
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["process", "calculate", "compute"]):
            return SemanticIntent.DATA_PROCESSING
        if any(keyword in node_name_lower for keyword in ["error", "exception", "handle"]):
            return SemanticIntent.ERROR_HANDLING
        if any(keyword in node_name_lower for keyword in ["log", "trace", "debug"]):
            return SemanticIntent.LOGGING
        if any(keyword in node_name_lower for keyword in ["config", "setting", "option"]):
            return SemanticIntent.CONFIGURATION
        return SemanticIntent.BUSINESS_LOGIC

    def _determine_business_pattern(self, nlp_features: dict[str, Any], node_name: str, content: str) -> BusinessLogicPattern | None:
        """Determine business logic pattern."""
        business_scores = nlp_features.get("business_scores", {})

        # Find highest scoring business pattern
        if business_scores:
            max_pattern = max(business_scores.items(), key=lambda x: x[1])
            if max_pattern[1] > 0:
                try:
                    return BusinessLogicPattern(max_pattern[0])
                except ValueError as e:
                    self.logger.error("Value error in semantic_code_analyzer: %s", e)

        # Fallback to name-based analysis
        node_name_lower = node_name.lower()
        content_lower = content.lower()

        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["license", "key", "activation"]):
            return BusinessLogicPattern.LICENSE_VALIDATION
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["user", "account", "profile"]):
            return BusinessLogicPattern.USER_MANAGEMENT
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["access", "permission", "role"]):
            return BusinessLogicPattern.ACCESS_CONTROL
        if any(keyword in node_name_lower or keyword in content_lower for keyword in ["validate", "check", "verify"]):
            return BusinessLogicPattern.DATA_VALIDATION
        if any(keyword in node_name_lower for keyword in ["audit", "log", "track"]):
            return BusinessLogicPattern.AUDIT_LOGGING

        return None

    def _calculate_node_confidence(self, nlp_features: dict[str, Any], semantic_intent: SemanticIntent) -> float:
        """Calculate confidence score for semantic node."""
        confidence = 0.5  # Base confidence

        # Add confidence boost for high-value intents
        high_value_intents = [
            SemanticIntent.AUTHENTICATION,
            SemanticIntent.ENCRYPTION,
            SemanticIntent.AUTHORIZATION,
            SemanticIntent.VALIDATION,
        ]
        if semantic_intent in high_value_intents:
            confidence += 0.1

        # Add confidence based on vocabulary matches
        vocab_matches = nlp_features.get("vocabulary_matches", {})
        if vocab_matches:
            max_vocab_score = max(vocab_matches.values())
            confidence += min(0.3, max_vocab_score * 0.1)

        # Add confidence based on pattern matches
        pattern_matches = nlp_features.get("pattern_matches", {})
        if pattern_matches:
            max_pattern_score = max(pattern_matches.values())
            confidence += min(0.2, max_pattern_score * 0.05)

        return min(1.0, confidence)

    def _analyze_relationships(self, semantic_nodes: list[SemanticNode]) -> list[SemanticRelationship]:
        """Analyze relationships between semantic nodes."""
        relationships = []

        for i, node1 in enumerate(semantic_nodes):
            for node2 in semantic_nodes[i + 1 :]:
                relationship = self._detect_relationship(node1, node2)
                if relationship:
                    relationships.append(relationship)

        return relationships

    def _detect_relationship(self, node1: SemanticNode, node2: SemanticNode) -> SemanticRelationship | None:
        """Detect relationship between two semantic nodes."""
        # Check for function calls
        if node2.name in node1.content or node1.name in node2.content:
            relationship_type = "calls"
            strength = 0.8
            confidence = 0.9

        # Check for similar semantic intent
        elif node1.semantic_intent == node2.semantic_intent:
            relationship_type = "similar_intent"
            strength = 0.6
            confidence = 0.7

        # Check for sequential processing
        elif node1.location["line"] < node2.location["line"] and abs(node1.location["line"] - node2.location["line"]) < 20:
            relationship_type = "sequential"
            strength = 0.4
            confidence = 0.6

        else:
            return None

        relationship_id = f"rel_{node1.node_id}_{node2.node_id}"

        return SemanticRelationship(
            relationship_id=relationship_id,
            source_node=node1.node_id,
            target_node=node2.node_id,
            relationship_type=relationship_type,
            strength=strength,
            confidence=confidence,
            description=f"{relationship_type} relationship between {node1.name} and {node2.name}",
        )

    def _detect_intent_mismatches(self, semantic_nodes: list[SemanticNode], content: str) -> list[IntentMismatch]:
        """Detect mismatches between intent and implementation."""
        mismatches = []

        for node in semantic_nodes:
            mismatch = self._analyze_node_for_mismatch(node, content)
            if mismatch:
                mismatches.append(mismatch)

        return mismatches

    def _analyze_node_for_mismatch(self, node: SemanticNode, content: str) -> IntentMismatch | None:
        """Analyze single node for intent mismatch."""
        # Use node content or fallback to full content for analysis
        analysis_content = node.content or content

        # Example: validation function that doesn't actually validate
        if node.semantic_intent == SemanticIntent.VALIDATION:
            if self._has_trivial_validation(analysis_content):
                return IntentMismatch(
                    mismatch_id=f"mismatch_{node.node_id}",
                    function_name=node.name,
                    expected_intent=SemanticIntent.VALIDATION,
                    actual_implementation="trivial_validation",
                    mismatch_type="insufficient_validation",
                    severity="medium",
                    confidence=0.8,
                    suggested_fixes=[
                        "Add proper input validation",
                        "Implement comprehensive checks",
                        "Add error handling for invalid inputs",
                    ],
                    evidence={
                        "trivial_patterns": self._find_trivial_patterns(analysis_content),
                        "missing_checks": self._find_missing_validation_checks(analysis_content),
                    },
                )

        # Example: authentication function with weak implementation
        elif node.semantic_intent == SemanticIntent.AUTHENTICATION:
            if self._has_weak_authentication(node.content):
                return IntentMismatch(
                    mismatch_id=f"mismatch_{node.node_id}",
                    function_name=node.name,
                    expected_intent=SemanticIntent.AUTHENTICATION,
                    actual_implementation="weak_authentication",
                    mismatch_type="security_weakness",
                    severity="high",
                    confidence=0.9,
                    suggested_fixes=[
                        "Implement proper password hashing",
                        "Add multi-factor authentication",
                        "Use secure session management",
                    ],
                    evidence={
                        "weak_patterns": self._find_weak_auth_patterns(node.content),
                    },
                )

        return None

    def _has_trivial_validation(self, content: str) -> bool:
        """Check if validation is trivial."""
        # Look for patterns indicating trivial validation
        trivial_patterns = [
            r"return\s+True",
            r"return\s+1",
            r'return\s+"ok"',
            r"pass\s*$",
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in trivial_patterns)

    def _has_weak_authentication(self, content: str) -> bool:
        """Check if authentication is weak."""
        weak_patterns = [
            r'password\s*==\s*["\']',  # Plain text password comparison
            r"if\s+password\s*:",  # Just checking if password exists
            r"return\s+True",  # Always returns true
        ]

        return any(re.search(pattern, content, re.IGNORECASE) for pattern in weak_patterns)

    def _find_trivial_patterns(self, content: str) -> list[str]:
        """Find trivial validation patterns."""
        patterns = []

        if re.search(r"return\s+True", content, re.IGNORECASE):
            patterns.append("always_returns_true")

        if re.search(r"pass\s*$", content, re.MULTILINE):
            patterns.append("empty_implementation")

        return patterns

    def _find_missing_validation_checks(self, content: str) -> list[str]:
        """Find missing validation checks."""
        missing = []

        if not re.search(r"if\s+not\s+", content):
            missing.append("null_check")

        if not re.search(r"len\s*\(", content):
            missing.append("length_check")

        if not re.search(r"isinstance\s*\(", content):
            missing.append("type_check")

        return missing

    def _find_weak_auth_patterns(self, content: str) -> list[str]:
        """Find weak authentication patterns."""
        patterns = []

        if re.search(r'password\s*==\s*["\']', content):
            patterns.append("plaintext_comparison")

        if not re.search(r"hash|encrypt|bcrypt|scrypt", content, re.IGNORECASE):
            patterns.append("no_hashing")

        return patterns

    def _map_business_logic(self, semantic_nodes: list[SemanticNode]) -> dict[str, BusinessLogicPattern]:
        """Map business logic patterns in the code."""
        business_map = {}

        for node in semantic_nodes:
            if node.business_pattern:
                business_map[node.node_id] = node.business_pattern

        return business_map

    def _calculate_complexity_metrics(self, semantic_nodes: list[SemanticNode], content: str) -> dict[str, float]:
        """Calculate complexity metrics."""
        return {
            "semantic_complexity": len(semantic_nodes),
            "intent_diversity": len({node.semantic_intent for node in semantic_nodes}),
            "business_pattern_count": len({node.business_pattern for node in semantic_nodes if node.business_pattern}),
            "avg_node_confidence": sum(node.confidence for node in semantic_nodes) / len(semantic_nodes) if semantic_nodes else 0,
            "content_length": len(content),
            "function_count": sum(1 for node in semantic_nodes if node.node_type.lower() == "functiondef"),
        }

    def _generate_semantic_summary(self, semantic_nodes: list[SemanticNode], relationships: list[SemanticRelationship]) -> dict[str, Any]:
        """Generate semantic summary."""
        intent_counts = Counter(node.semantic_intent for node in semantic_nodes)
        pattern_counts = Counter(node.business_pattern for node in semantic_nodes if node.business_pattern)

        return {
            "total_nodes": len(semantic_nodes),
            "total_relationships": len(relationships),
            "intent_distribution": {intent.value: count for intent, count in intent_counts.items()},
            "business_pattern_distribution": {pattern.value: count for pattern, count in pattern_counts.items()},
            "primary_intent": intent_counts.most_common(1)[0][0].value if intent_counts else "unknown",
            "complexity_level": self._assess_complexity_level(semantic_nodes),
        }

    def _assess_complexity_level(self, semantic_nodes: list[SemanticNode]) -> str:
        """Assess complexity level of the code."""
        if len(semantic_nodes) < 5:
            return "low"
        if len(semantic_nodes) < 15:
            return "medium"
        return "high"

    def _calculate_analysis_confidence(self, semantic_nodes: list[SemanticNode], relationships: list[SemanticRelationship]) -> float:
        """Calculate overall analysis confidence."""
        if not semantic_nodes:
            return 0.0

        node_confidences = [node.confidence for node in semantic_nodes]
        relationship_confidences = [rel.confidence for rel in relationships]

        avg_node_confidence = sum(node_confidences) / len(node_confidences)
        avg_rel_confidence = sum(relationship_confidences) / len(relationship_confidences) if relationship_confidences else 0.5

        # Weight node confidence more heavily
        overall_confidence = (avg_node_confidence * 0.7) + (avg_rel_confidence * 0.3)

        return min(1.0, overall_confidence)

    def _calculate_file_hash(self, file_path: str, content: str | None) -> str:
        """Calculate hash for caching."""
        if content is None:
            try:
                from .ai_file_tools import get_ai_file_tools

                ai_file_tools = get_ai_file_tools(getattr(self, "app_instance", None))
                file_data = ai_file_tools.read_file(file_path, purpose="File hash calculation for caching")
                if file_data.get("status") == "success" and file_data.get("content"):
                    content = file_data["content"]
                else:
                    # Fallback to direct file reading
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
            except (ImportError, AttributeError, KeyError):
                # AIFileTools not available, use direct file reading
                try:
                    with open(file_path, encoding="utf-8") as f:
                        content = f.read()
                except Exception as e:
                    self.logger.error("Exception in semantic_code_analyzer: %s", e)
                    content = ""
            except Exception as e:
                self.logger.error("Exception in semantic_code_analyzer: %s", e)
                content = ""

        return hashlib.md5(f"{file_path}:{content}".encode(), usedforsecurity=False).hexdigest()

    def _create_empty_result(self, file_path: str) -> SemanticAnalysisResult:
        """Create empty analysis result for failed analysis."""
        return SemanticAnalysisResult(
            analysis_id="empty",
            file_path=file_path,
            semantic_nodes=[],
            relationships=[],
            intent_mismatches=[],
            business_logic_map={},
            complexity_metrics={},
            semantic_summary={},
            confidence=0.0,
            analysis_time=0.0,
        )

    def get_semantic_insights(self, file_paths: list[str]) -> dict[str, Any]:
        """Get semantic insights across multiple files."""
        insights = {
            "files_analyzed": len(file_paths),
            "total_nodes": 0,
            "total_relationships": 0,
            "intent_distribution": Counter(),
            "business_pattern_distribution": Counter(),
            "mismatches_found": 0,
            "avg_confidence": 0.0,
            "complexity_overview": {},
        }

        all_results = []

        for file_path in file_paths:
            try:
                result = self.analyze_file(file_path)
                all_results.append(result)

                insights["total_nodes"] += len(result.semantic_nodes)
                insights["total_relationships"] += len(result.relationships)
                insights["mismatches_found"] += len(result.intent_mismatches)

                # Update intent distribution
                for node in result.semantic_nodes:
                    insights["intent_distribution"][node.semantic_intent.value] += 1

                # Update business pattern distribution
                for pattern in result.business_logic_map.values():
                    insights["business_pattern_distribution"][pattern.value] += 1

            except Exception as e:
                logger.error(f"Failed to analyze {file_path}: {e}")

        # Calculate average confidence
        if all_results:
            insights["avg_confidence"] = sum(r.confidence for r in all_results) / len(all_results)

        # Complexity overview
        insights["complexity_overview"] = {
            "simple_files": len([r for r in all_results if len(r.semantic_nodes) < 5]),
            "moderate_files": len([r for r in all_results if 5 <= len(r.semantic_nodes) < 15]),
            "complex_files": len([r for r in all_results if len(r.semantic_nodes) >= 15]),
        }

        return insights


class SemanticKnowledgeBase:
    """Knowledge base for semantic patterns and rules."""

    def __init__(self) -> None:
        """Initialize the semantic knowledge base.

        Sets up pattern storage, rule definitions, and anti-pattern
        tracking for semantic code analysis and pattern recognition.
        """
        self.patterns: dict[str, dict[str, Any]] = {}
        self.rules: dict[str, dict[str, Any]] = {}
        self.anti_patterns: dict[str, dict[str, Any]] = {}

        self._initialize_knowledge_base()

    def _initialize_knowledge_base(self) -> None:
        """Initialize knowledge base with common patterns."""
        # Security patterns
        self.patterns["security_validation"] = {
            "description": "Proper input validation for security",
            "indicators": ["sanitize", "escape", "validate", "filter"],
            "required_checks": ["null_check", "length_check", "format_check"],
            "confidence_boost": 0.2,
        }

        # Authentication patterns
        self.patterns["strong_authentication"] = {
            "description": "Strong authentication implementation",
            "indicators": ["hash", "salt", "bcrypt", "scrypt", "pbkdf2"],
            "required_features": ["password_hashing", "session_management"],
            "confidence_boost": 0.3,
        }

        # Anti-patterns
        self.anti_patterns["weak_validation"] = {
            "description": "Weak or missing validation",
            "indicators": ["return True", "pass", "# TODO"],
            "severity": "medium",
            "confidence_penalty": 0.3,
        }

        self.anti_patterns["hardcoded_credentials"] = {
            "description": "Hardcoded passwords or keys",
            "indicators": ['password = "', 'key = "', 'secret = "'],
            "severity": "high",
            "confidence_penalty": 0.5,
        }


# Global semantic analyzer instance
semantic_analyzer = SemanticCodeAnalyzer()
