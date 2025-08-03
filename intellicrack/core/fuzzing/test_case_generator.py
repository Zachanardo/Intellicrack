"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

AI-powered test case generator for intelligent fuzzing with grammar-based
and structure-aware generation capabilities.
"""

import json
import os
import random
import string
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from intellicrack.utils.logger import logger

try:
    from ...ai.llm_backends import LLMBackends
    from ...ai.predictive_intelligence import PredictiveIntelligence
    from ...ai.multi_agent_system import MultiAgentSystem
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


class GenerationStrategy(Enum):
    """Test case generation strategies."""
    RANDOM = "random"
    GRAMMAR_BASED = "grammar_based"
    STRUCTURE_AWARE = "structure_aware"
    TEMPLATE_BASED = "template_based"
    AI_GUIDED = "ai_guided"
    MUTATION_BASED = "mutation_based"
    EVOLUTIONARY = "evolutionary"


class InputFormat(Enum):
    """Supported input formats."""
    BINARY = "binary"
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    NETWORK_PACKET = "network_packet"
    FILE_FORMAT = "file_format"
    API_CALL = "api_call"
    COMMAND_LINE = "command_line"


@dataclass
class GrammarRule:
    """Grammar rule for generation."""
    name: str
    alternatives: List[str]
    weight: float = 1.0
    context_sensitive: bool = False
    min_depth: int = 0
    max_depth: int = 10


@dataclass
class StructureTemplate:
    """Template for structured input generation."""
    name: str
    fields: List[Dict[str, Any]]
    dependencies: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestCaseMetadata:
    """Metadata for generated test cases."""
    generation_strategy: GenerationStrategy
    source_template: Optional[str] = None
    grammar_rules_used: List[str] = field(default_factory=list)
    ai_confidence: float = 0.0
    expected_coverage: Set[str] = field(default_factory=set)
    mutation_lineage: List[str] = field(default_factory=list)
    generation_time: float = 0.0


@dataclass
class GeneratedTestCase:
    """Generated test case with metadata."""
    data: bytes
    metadata: TestCaseMetadata
    input_format: InputFormat
    size: int = 0
    checksum: str = ""
    
    def __post_init__(self):
        self.size = len(self.data)
        import hashlib
        self.checksum = hashlib.md5(self.data).hexdigest()


class BaseGenerator(ABC):
    """Base class for test case generators."""
    
    def __init__(self, name: str):
        self.name = name
        self.generation_count = 0
        self.success_rate = 0.0
        self.average_generation_time = 0.0
        
    @abstractmethod
    def generate(self, target_size: int, context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate a test case."""
        pass
    
    def update_metrics(self, generation_time: float, success: bool):
        """Update generator metrics."""
        self.generation_count += 1
        
        # Update average generation time
        if self.generation_count == 1:
            self.average_generation_time = generation_time
        else:
            self.average_generation_time = (
                (self.average_generation_time * (self.generation_count - 1) + generation_time)
                / self.generation_count
            )
        
        # Update success rate
        if success:
            self.success_rate = (
                (self.success_rate * (self.generation_count - 1) + 1.0)
                / self.generation_count
            )
        else:
            self.success_rate = (
                self.success_rate * (self.generation_count - 1)
                / self.generation_count
            )


class RandomGenerator(BaseGenerator):
    """Random test case generator."""
    
    def __init__(self):
        super().__init__("random")
        
    def generate(self, target_size: int, context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate random test case."""
        start_time = time.time()
        
        # Generate random bytes
        data = os.urandom(target_size)
        
        metadata = TestCaseMetadata(
            generation_strategy=GenerationStrategy.RANDOM,
            generation_time=time.time() - start_time
        )
        
        return GeneratedTestCase(
            data=data,
            metadata=metadata,
            input_format=InputFormat.BINARY
        )


class GrammarBasedGenerator(BaseGenerator):
    """Grammar-based test case generator."""
    
    def __init__(self):
        super().__init__("grammar_based")
        self.grammars: Dict[str, List[GrammarRule]] = {}
        self.load_default_grammars()
        
    def load_default_grammars(self):
        """Load default grammar rules."""
        # HTTP grammar
        self.grammars["http"] = [
            GrammarRule("request", ["<method> <path> <version>\\r\\n<headers>\\r\\n\\r\\n<body>"]),
            GrammarRule("method", ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
            GrammarRule("path", ["/", "/<word>", "/<word>/<word>", "/<word>?<params>"]),
            GrammarRule("version", ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0"]),
            GrammarRule("headers", ["<header>", "<header>\\r\\n<headers>"]),
            GrammarRule("header", ["<header_name>: <header_value>"]),
            GrammarRule("header_name", ["Host", "User-Agent", "Content-Type", "Content-Length"]),
            GrammarRule("header_value", ["<word>", "<number>", "<word>/<word>"]),
            GrammarRule("params", ["<param>", "<param>&<params>"]),
            GrammarRule("param", ["<word>=<word>"]),
            GrammarRule("body", ["", "<word>", "<json>", "<xml>"]),
            GrammarRule("word", [self._generate_word]),
            GrammarRule("number", [self._generate_number]),
            GrammarRule("json", [self._generate_json]),
            GrammarRule("xml", [self._generate_xml])
        ]
        
        # File format grammar (simplified PE)
        self.grammars["pe"] = [
            GrammarRule("file", ["<dos_header><pe_header><sections>"]),
            GrammarRule("dos_header", ["MZ<dos_data>"]),
            GrammarRule("dos_data", [self._generate_dos_data]),
            GrammarRule("pe_header", ["PE\\x00\\x00<coff_header><optional_header>"]),
            GrammarRule("coff_header", [self._generate_coff_header]),
            GrammarRule("optional_header", [self._generate_optional_header]),
            GrammarRule("sections", ["<section>", "<section><sections>"]),
            GrammarRule("section", ["<section_header><section_data>"]),
            GrammarRule("section_header", [self._generate_section_header]),
            GrammarRule("section_data", [self._generate_section_data])
        ]
        
    def load_grammar(self, name: str, rules: List[GrammarRule]):
        """Load custom grammar rules."""
        self.grammars[name] = rules
        
    def generate(self, target_size: int, context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate test case using grammar rules."""
        start_time = time.time()
        
        grammar_name = context.get("grammar", "http")
        if grammar_name not in self.grammars:
            grammar_name = "http"
            
        rules_used = []
        data = self._expand_rule("request" if grammar_name == "http" else "file", 
                                grammar_name, rules_used, max_depth=10)
        
        # Adjust size if needed
        if len(data) > target_size:
            data = data[:target_size]
        elif len(data) < target_size:
            padding = os.urandom(target_size - len(data))
            data += padding
            
        metadata = TestCaseMetadata(
            generation_strategy=GenerationStrategy.GRAMMAR_BASED,
            source_template=grammar_name,
            grammar_rules_used=rules_used,
            generation_time=time.time() - start_time
        )
        
        return GeneratedTestCase(
            data=data,
            metadata=metadata,
            input_format=InputFormat.TEXT if grammar_name == "http" else InputFormat.FILE_FORMAT
        )
        
    def _expand_rule(self, rule_name: str, grammar_name: str, rules_used: List[str], 
                    depth: int = 0, max_depth: int = 10) -> bytes:
        """Expand a grammar rule recursively."""
        if depth > max_depth:
            return b""
            
        rules = self.grammars.get(grammar_name, [])
        rule = next((r for r in rules if r.name == rule_name), None)
        
        if not rule:
            return rule_name.encode()
            
        rules_used.append(rule_name)
        alternative = random.choice(rule.alternatives)
        
        if callable(alternative):
            return alternative()
            
        result = b""
        i = 0
        while i < len(alternative):
            if alternative[i] == '<':
                # Find closing bracket
                end = alternative.find('>', i)
                if end != -1:
                    subrule = alternative[i+1:end]
                    result += self._expand_rule(subrule, grammar_name, rules_used, depth + 1, max_depth)
                    i = end + 1
                else:
                    result += alternative[i].encode()
                    i += 1
            else:
                # Handle escape sequences
                if alternative[i:i+2] == "\\r":
                    result += b"\r"
                    i += 2
                elif alternative[i:i+2] == "\\n":
                    result += b"\n"
                    i += 2
                elif alternative[i:i+4] == "\\x00":
                    result += b"\x00"
                    i += 4
                else:
                    result += alternative[i].encode()
                    i += 1
                    
        return result
        
    def _generate_word(self) -> bytes:
        """Generate random word."""
        length = random.randint(1, 20)
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length)).encode()
        
    def _generate_number(self) -> bytes:
        """Generate random number."""
        return str(random.randint(0, 99999)).encode()
        
    def _generate_json(self) -> bytes:
        """Generate simple JSON."""
        data = {
            "key": "value",
            "number": random.randint(1, 1000),
            "array": [1, 2, 3]
        }
        return json.dumps(data).encode()
        
    def _generate_xml(self) -> bytes:
        """Generate simple XML."""
        return b"<root><item>value</item></root>"
        
    def _generate_dos_data(self) -> bytes:
        """Generate DOS header data."""
        return struct.pack("<H", 0x5A4D) + os.urandom(58)
        
    def _generate_coff_header(self) -> bytes:
        """Generate COFF header."""
        return struct.pack("<HHIIIHH", 
                          0x014c,  # machine
                          1,       # number of sections
                          int(time.time()),  # timestamp
                          0,       # pointer to symbol table
                          0,       # number of symbols
                          224,     # size of optional header
                          0x102)   # characteristics
                          
    def _generate_optional_header(self) -> bytes:
        """Generate optional header."""
        return os.urandom(224)  # Simplified
        
    def _generate_section_header(self) -> bytes:
        """Generate section header."""
        return b".text\x00\x00\x00" + os.urandom(32)
        
    def _generate_section_data(self) -> bytes:
        """Generate section data."""
        return os.urandom(random.randint(100, 1000))


class StructureAwareGenerator(BaseGenerator):
    """Structure-aware test case generator."""
    
    def __init__(self):
        super().__init__("structure_aware")
        self.templates: Dict[str, StructureTemplate] = {}
        self.load_default_templates()
        
    def load_default_templates(self):
        """Load default structure templates."""
        # Binary file template
        self.templates["binary_file"] = StructureTemplate(
            name="binary_file",
            fields=[
                {"name": "magic", "type": "bytes", "size": 4, "values": [b"MZ\x90\x00", b"\x7fELF"]},
                {"name": "header", "type": "struct", "format": "<HHI", "random": True},
                {"name": "data", "type": "random", "size": "variable"},
                {"name": "checksum", "type": "checksum", "algorithm": "crc32"}
            ]
        )
        
        # Network packet template
        self.templates["network_packet"] = StructureTemplate(
            name="network_packet",
            fields=[
                {"name": "ethernet_header", "type": "struct", "format": "!6s6sH"},
                {"name": "ip_header", "type": "struct", "format": "!BBHHHBBH4s4s"},
                {"name": "tcp_header", "type": "struct", "format": "!HHLLBBHHH"},
                {"name": "payload", "type": "random", "size": "variable"}
            ]
        )
        
        # JSON API request template
        self.templates["json_api"] = StructureTemplate(
            name="json_api",
            fields=[
                {"name": "method", "type": "choice", "values": ["GET", "POST", "PUT", "DELETE"]},
                {"name": "endpoint", "type": "string", "pattern": "/api/v1/<resource>/<id>"},
                {"name": "headers", "type": "dict", "keys": ["Content-Type", "Authorization"]},
                {"name": "body", "type": "json", "schema": {"user_id": "int", "data": "string"}}
            ]
        )
        
    def add_template(self, template: StructureTemplate):
        """Add custom structure template."""
        self.templates[template.name] = template
        
    def generate(self, target_size: int, context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate structured test case."""
        start_time = time.time()
        
        template_name = context.get("template", "binary_file")
        template = self.templates.get(template_name)
        
        if not template:
            # Fall back to random generation
            data = os.urandom(target_size)
        else:
            data = self._generate_from_template(template, target_size)
            
        metadata = TestCaseMetadata(
            generation_strategy=GenerationStrategy.STRUCTURE_AWARE,
            source_template=template_name,
            generation_time=time.time() - start_time
        )
        
        return GeneratedTestCase(
            data=data,
            metadata=metadata,
            input_format=self._get_input_format(template_name)
        )
        
    def _generate_from_template(self, template: StructureTemplate, target_size: int) -> bytes:
        """Generate data from structure template."""
        result = b""
        
        for field in template.fields:
            field_data = self._generate_field(field, target_size - len(result))
            result += field_data
            
            if len(result) >= target_size:
                break
                
        # Pad or truncate to target size
        if len(result) < target_size:
            result += os.urandom(target_size - len(result))
        elif len(result) > target_size:
            result = result[:target_size]
            
        return result
        
    def _generate_field(self, field: Dict[str, Any], remaining_size: int) -> bytes:
        """Generate data for a single field."""
        field_type = field.get("type", "random")
        
        if field_type == "bytes":
            if "values" in field:
                return random.choice(field["values"])
            else:
                size = field.get("size", 4)
                return os.urandom(size)
                
        elif field_type == "struct":
            format_str = field.get("format", "<I")
            if field.get("random", False):
                # Generate random values for struct
                import struct as struct_mod
                size = struct_mod.calcsize(format_str)
                values = []
                for _ in range(format_str.count("H") + format_str.count("I") + format_str.count("L")):
                    values.append(random.randint(0, 65535))
                return struct.pack(format_str, *values[:struct_mod.calcsize(format_str)//4])
            else:
                return struct.pack(format_str, 0)
                
        elif field_type == "random":
            size = field.get("size", remaining_size)
            if size == "variable":
                size = random.randint(1, min(remaining_size, 1024))
            return os.urandom(size)
            
        elif field_type == "choice":
            values = field.get("values", ["default"])
            return random.choice(values).encode() if isinstance(random.choice(values), str) else random.choice(values)
            
        elif field_type == "string":
            pattern = field.get("pattern", "random_string")
            return self._generate_string_from_pattern(pattern).encode()
            
        elif field_type == "dict":
            keys = field.get("keys", ["key"])
            result = {}
            for key in keys:
                result[key] = f"value_{random.randint(1, 1000)}"
            return json.dumps(result).encode()
            
        elif field_type == "json":
            schema = field.get("schema", {})
            return json.dumps(self._generate_json_from_schema(schema)).encode()
            
        elif field_type == "checksum":
            # Real checksum calculation based on target data
            import zlib, hashlib
            
            # Get target data for checksum calculation
            target_data = kwargs.get('target_data', b'')
            checksum_type = kwargs.get('checksum_type', 'crc32')
            checksum_offset = kwargs.get('checksum_offset', 0)
            
            if checksum_type == "crc32":
                # Calculate CRC32 checksum
                if target_data:
                    crc_data = target_data[:checksum_offset] + target_data[checksum_offset+4:]
                    checksum = zlib.crc32(crc_data) & 0xffffffff
                else:
                    # Generate realistic test checksum
                    test_data = os.urandom(random.randint(100, 1000))
                    checksum = zlib.crc32(test_data) & 0xffffffff
                return struct.pack("<I", checksum)
            
            elif checksum_type == "md5":
                if target_data:
                    md5_data = target_data[:checksum_offset] + target_data[checksum_offset+16:]
                    checksum = hashlib.md5(md5_data).digest()
                else:
                    checksum = hashlib.md5(os.urandom(random.randint(100, 1000))).digest()
                return checksum
            
            elif checksum_type == "sha1":
                if target_data:
                    sha1_data = target_data[:checksum_offset] + target_data[checksum_offset+20:]
                    checksum = hashlib.sha1(sha1_data).digest()
                else:
                    checksum = hashlib.sha1(os.urandom(random.randint(100, 1000))).digest()
                return checksum
            
            else:
                # Default to CRC32
                test_data = os.urandom(random.randint(100, 1000))
                checksum = zlib.crc32(test_data) & 0xffffffff
                return struct.pack("<I", checksum)
            
        else:
            return os.urandom(4)
            
    def _generate_string_from_pattern(self, pattern: str) -> str:
        """Generate string from pattern."""
        if "<resource>" in pattern:
            resources = ["users", "posts", "comments", "files"]
            pattern = pattern.replace("<resource>", random.choice(resources))
        if "<id>" in pattern:
            pattern = pattern.replace("<id>", str(random.randint(1, 1000)))
        return pattern
        
    def _generate_json_from_schema(self, schema: Dict[str, str]) -> Dict[str, Any]:
        """Generate JSON from schema."""
        result = {}
        for key, value_type in schema.items():
            if value_type == "int":
                result[key] = random.randint(1, 1000)
            elif value_type == "string":
                result[key] = f"test_value_{random.randint(1, 100)}"
            elif value_type == "bool":
                result[key] = random.choice([True, False])
            else:
                result[key] = "default_value"
        return result
        
    def _get_input_format(self, template_name: str) -> InputFormat:
        """Get input format for template."""
        format_map = {
            "binary_file": InputFormat.FILE_FORMAT,
            "network_packet": InputFormat.NETWORK_PACKET,
            "json_api": InputFormat.JSON
        }
        return format_map.get(template_name, InputFormat.BINARY)


class AIGuidedGenerator(BaseGenerator):
    """AI-guided test case generator."""
    
    def __init__(self):
        super().__init__("ai_guided")
        self.llm_backends = None
        self.predictive_intelligence = None
        self.multi_agent = None
        
        if LLM_AVAILABLE:
            try:
                self.llm_backends = LLMBackends()
                self.predictive_intelligence = PredictiveIntelligence()
                self.multi_agent = MultiAgentSystem()
            except Exception as e:
                logger.debug(f"AI components not available: {e}")
                
    def generate(self, target_size: int, context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate AI-guided test case."""
        start_time = time.time()
        
        if not self.llm_backends:
            # Fall back to random generation
            data = os.urandom(target_size)
            ai_confidence = 0.0
        else:
            data, ai_confidence = self._generate_with_ai(target_size, context)
            
        metadata = TestCaseMetadata(
            generation_strategy=GenerationStrategy.AI_GUIDED,
            ai_confidence=ai_confidence,
            generation_time=time.time() - start_time
        )
        
        return GeneratedTestCase(
            data=data,
            metadata=metadata,
            input_format=context.get("format", InputFormat.BINARY)
        )
        
    def _generate_with_ai(self, target_size: int, context: Dict[str, Any]) -> Tuple[bytes, float]:
        """Generate test case using AI guidance."""
        try:
            target_info = context.get("target_info", {})
            target_type = target_info.get("type", "binary")
            
            # Use LLM to generate strategy
            prompt = f"""
            Generate a test case for fuzzing a {target_type} target.
            Target size: {target_size} bytes
            Context: {context}
            
            Provide specific byte sequences that would be effective for testing:
            1. Header/magic bytes
            2. Size fields
            3. Boundary conditions
            4. Edge cases
            
            Format as hexadecimal sequences.
            """
            
            response = self.llm_backends.generate_response(prompt, max_tokens=500)
            
            # Parse AI response and generate bytes
            ai_suggestions = response.get("content", "")
            data = self._parse_ai_suggestions(ai_suggestions, target_size)
            confidence = response.get("confidence", 0.5)
            
            return data, confidence
            
        except Exception as e:
            logger.debug(f"AI generation failed: {e}")
            return os.urandom(target_size), 0.0
            
    def _parse_ai_suggestions(self, suggestions: str, target_size: int) -> bytes:
        """Parse AI suggestions into byte data."""
        result = b""
        
        # Look for hex patterns in suggestions
        import re
        hex_patterns = re.findall(r'[0-9a-fA-F]{2,}', suggestions)
        
        for pattern in hex_patterns:
            try:
                if len(pattern) % 2 == 0:
                    hex_bytes = bytes.fromhex(pattern)
                    result += hex_bytes
                    
                    if len(result) >= target_size:
                        break
            except ValueError:
                continue
                
        # Fill remaining space with smart padding
        if len(result) < target_size:
            remaining = target_size - len(result)
            
            # Add some common patterns
            patterns = [
                b"\x00" * 4,  # Null padding
                b"\xFF" * 4,  # Max values
                b"\x41" * 4,  # 'AAAA'
                b"\x90" * 4   # NOP sled
            ]
            
            while remaining > 0 and result:
                pattern = random.choice(patterns)
                chunk_size = min(len(pattern), remaining)
                result += pattern[:chunk_size]
                remaining -= chunk_size
                
            # Fill any remaining space with random data
            if remaining > 0:
                result += os.urandom(remaining)
                
        return result[:target_size]


class TestCaseGenerator:
    """Main test case generator orchestrator."""
    
    def __init__(self):
        self.logger = logger.getChild("TestCaseGenerator")
        
        # Initialize generators
        self.generators = {
            GenerationStrategy.RANDOM: RandomGenerator(),
            GenerationStrategy.GRAMMAR_BASED: GrammarBasedGenerator(),
            GenerationStrategy.STRUCTURE_AWARE: StructureAwareGenerator(),
            GenerationStrategy.AI_GUIDED: AIGuidedGenerator()
        }
        
        # Generation statistics
        self.total_generated = 0
        self.generation_history = []
        self.strategy_performance = {}
        
        # Corpus management
        self.seed_corpus = []
        self.interesting_inputs = []
        
        self.logger.info("Test case generator initialized")
        
    def add_seed_input(self, data: bytes, metadata: Optional[Dict[str, Any]] = None):
        """Add seed input to corpus."""
        self.seed_corpus.append({
            "data": data,
            "metadata": metadata or {},
            "added_time": time.time()
        })
        self.logger.debug(f"Added seed input ({len(data)} bytes)")
        
    def generate_batch(self, count: int, strategy: GenerationStrategy,
                      target_size: int, context: Dict[str, Any]) -> List[GeneratedTestCase]:
        """Generate batch of test cases."""
        test_cases = []
        
        for i in range(count):
            try:
                test_case = self.generate_single(strategy, target_size, context)
                test_cases.append(test_case)
                
                # Update statistics
                self.total_generated += 1
                self.generation_history.append({
                    "strategy": strategy,
                    "size": len(test_case.data),
                    "timestamp": time.time()
                })
                
            except Exception as e:
                self.logger.error(f"Failed to generate test case {i+1}/{count}: {e}")
                
        self.logger.info(f"Generated {len(test_cases)}/{count} test cases using {strategy.value}")
        return test_cases
        
    def generate_single(self, strategy: GenerationStrategy, target_size: int,
                       context: Dict[str, Any]) -> GeneratedTestCase:
        """Generate single test case."""
        generator = self.generators.get(strategy)
        if not generator:
            self.logger.warning(f"Unknown strategy {strategy}, falling back to random")
            generator = self.generators[GenerationStrategy.RANDOM]
            
        start_time = time.time()
        test_case = generator.generate(target_size, context)
        generation_time = time.time() - start_time
        
        # Update generator metrics
        generator.update_metrics(generation_time, True)
        
        # Update strategy performance
        if strategy not in self.strategy_performance:
            self.strategy_performance[strategy] = {
                "total_generated": 0,
                "total_time": 0.0,
                "average_time": 0.0
            }
            
        perf = self.strategy_performance[strategy]
        perf["total_generated"] += 1
        perf["total_time"] += generation_time
        perf["average_time"] = perf["total_time"] / perf["total_generated"]
        
        return test_case
        
    def generate_diverse_batch(self, count: int, target_size: int,
                             context: Dict[str, Any]) -> List[GeneratedTestCase]:
        """Generate diverse batch using multiple strategies."""
        strategies = list(self.generators.keys())
        test_cases = []
        
        # Distribute count across strategies
        per_strategy = max(1, count // len(strategies))
        remaining = count
        
        for strategy in strategies:
            if remaining <= 0:
                break
                
            batch_size = min(per_strategy, remaining)
            batch = self.generate_batch(batch_size, strategy, target_size, context)
            test_cases.extend(batch)
            remaining -= len(batch)
            
        # Generate remaining with best performing strategy
        if remaining > 0:
            best_strategy = self._get_best_strategy()
            final_batch = self.generate_batch(remaining, best_strategy, target_size, context)
            test_cases.extend(final_batch)
            
        return test_cases
        
    def mutate_interesting_input(self, input_data: bytes, mutations: int = 5) -> List[GeneratedTestCase]:
        """Mutate an interesting input to generate variants."""
        test_cases = []
        
        for i in range(mutations):
            mutated = self._apply_mutations(input_data)
            
            metadata = TestCaseMetadata(
                generation_strategy=GenerationStrategy.MUTATION_BASED,
                mutation_lineage=[f"mutation_{i}"]
            )
            
            test_case = GeneratedTestCase(
                data=mutated,
                metadata=metadata,
                input_format=InputFormat.BINARY
            )
            
            test_cases.append(test_case)
            
        return test_cases
        
    def _apply_mutations(self, data: bytes) -> bytes:
        """Apply random mutations to data."""
        if not data:
            return data
            
        data = bytearray(data)
        mutation_count = random.randint(1, 5)
        
        for _ in range(mutation_count):
            mutation_type = random.choice([
                "bit_flip", "byte_flip", "arithmetic", "insert", "delete", "splice"
            ])
            
            if mutation_type == "bit_flip":
                pos = random.randint(0, len(data) - 1)
                bit = random.randint(0, 7)
                data[pos] ^= (1 << bit)
                
            elif mutation_type == "byte_flip":
                pos = random.randint(0, len(data) - 1)
                data[pos] = random.randint(0, 255)
                
            elif mutation_type == "arithmetic":
                pos = random.randint(0, len(data) - 1)
                delta = random.randint(-10, 10)
                data[pos] = (data[pos] + delta) % 256
                
            elif mutation_type == "insert":
                pos = random.randint(0, len(data))
                insert_data = os.urandom(random.randint(1, 10))
                data[pos:pos] = insert_data
                
            elif mutation_type == "delete":
                if len(data) > 1:
                    pos = random.randint(0, len(data) - 1)
                    del data[pos]
                    
            elif mutation_type == "splice":
                if len(self.seed_corpus) > 0:
                    seed = random.choice(self.seed_corpus)
                    seed_data = seed["data"]
                    if len(seed_data) > 0:
                        splice_size = min(10, len(seed_data))
                        splice_start = random.randint(0, len(seed_data) - splice_size)
                        splice_data = seed_data[splice_start:splice_start + splice_size]
                        
                        pos = random.randint(0, len(data))
                        data[pos:pos] = splice_data
                        
        return bytes(data)
        
    def _get_best_strategy(self) -> GenerationStrategy:
        """Get best performing strategy."""
        if not self.strategy_performance:
            return GenerationStrategy.RANDOM
            
        # Score strategies based on generation count and time
        best_strategy = GenerationStrategy.RANDOM
        best_score = 0.0
        
        for strategy, perf in self.strategy_performance.items():
            # Higher generation count is better, lower time is better
            score = perf["total_generated"] / (perf["average_time"] + 0.1)
            if score > best_score:
                best_score = score
                best_strategy = strategy
                
        return best_strategy
        
    def mark_interesting(self, test_case: GeneratedTestCase, reason: str):
        """Mark a test case as interesting for future mutation."""
        self.interesting_inputs.append({
            "test_case": test_case,
            "reason": reason,
            "timestamp": time.time()
        })
        
        # Limit interesting inputs to prevent memory growth
        if len(self.interesting_inputs) > 1000:
            self.interesting_inputs = self.interesting_inputs[-500:]
            
        self.logger.debug(f"Marked test case as interesting: {reason}")
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics."""
        return {
            "total_generated": self.total_generated,
            "seed_corpus_size": len(self.seed_corpus),
            "interesting_inputs": len(self.interesting_inputs),
            "strategy_performance": self.strategy_performance,
            "generator_metrics": {
                name: {
                    "generation_count": gen.generation_count,
                    "success_rate": gen.success_rate,
                    "average_time": gen.average_generation_time
                }
                for name, gen in self.generators.items()
            }
        }
        
    def export_corpus(self, output_dir: str):
        """Export corpus to directory."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Export seed corpus
        seed_dir = os.path.join(output_dir, "seeds")
        os.makedirs(seed_dir, exist_ok=True)
        
        for i, seed in enumerate(self.seed_corpus):
            seed_path = os.path.join(seed_dir, f"seed_{i:04d}.bin")
            with open(seed_path, "wb") as f:
                f.write(seed["data"])
                
        # Export interesting inputs
        interesting_dir = os.path.join(output_dir, "interesting")
        os.makedirs(interesting_dir, exist_ok=True)
        
        for i, interesting in enumerate(self.interesting_inputs):
            interesting_path = os.path.join(interesting_dir, f"interesting_{i:04d}.bin")
            with open(interesting_path, "wb") as f:
                f.write(interesting["test_case"].data)
                
        self.logger.info(f"Exported corpus to {output_dir}")
        
    def load_corpus(self, input_dir: str):
        """Load corpus from directory."""
        import os
        
        # Load seed corpus
        seed_dir = os.path.join(input_dir, "seeds")
        if os.path.exists(seed_dir):
            for filename in os.listdir(seed_dir):
                if filename.endswith(".bin"):
                    filepath = os.path.join(seed_dir, filename)
                    with open(filepath, "rb") as f:
                        data = f.read()
                        self.add_seed_input(data)
                        
        self.logger.info(f"Loaded corpus from {input_dir}")