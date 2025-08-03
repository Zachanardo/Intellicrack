"""
Intelligent Mutation Engine - AI-powered input mutation strategies

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

import asyncio
import logging
import random
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable
import json
import numpy as np

from ...utils.logger import get_logger

logger = get_logger(__name__)


class MutationType(Enum):
    """Types of mutations that can be applied."""
    RANDOM = "random"
    ARITHMETIC = "arithmetic"
    BITFLIP = "bitflip"
    INTERESTING_VALUES = "interesting_values"
    DICTIONARY = "dictionary"
    SPLICE = "splice"
    STRUCTURE_AWARE = "structure_aware"
    GRAMMAR_BASED = "grammar_based"
    AI_GUIDED = "ai_guided"
    EVOLUTIONARY = "evolutionary"
    NEURAL_NETWORK = "neural_network"


class MutationStrategy(Enum):
    """High-level mutation strategies."""
    EXPLORATORY = "exploratory"
    EXPLOITATIVE = "exploitative"
    COVERAGE_GUIDED = "coverage_guided"
    VULNERABILITY_TARGETED = "vulnerability_targeted"
    FORMAT_AWARE = "format_aware"
    API_FOCUSED = "api_focused"


@dataclass
class MutationResult:
    """Result of a mutation operation."""
    success: bool
    data: bytes
    mutation_type: MutationType
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    generation_time: float = 0.0
    size_change: int = 0
    complexity_score: float = 0.0


@dataclass
class StructuralMutation:
    """Structural mutation for format-aware fuzzing."""
    field_name: str
    field_type: str
    offset: int
    size: int
    mutation_strategy: str
    semantic_meaning: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class GrammarMutation:
    """Grammar-based mutation definition."""
    production_rule: str
    replacement_options: List[str]
    context_requirements: List[str] = field(default_factory=list)
    semantic_constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIGuidedMutation:
    """AI-guided mutation with learned patterns."""
    target_pattern: str
    learned_effectiveness: float
    context_vector: List[float]
    success_history: List[bool] = field(default_factory=list)
    adaptation_parameters: Dict[str, float] = field(default_factory=dict)


class BaseMutator(ABC):
    """Base class for all mutators."""
    
    def __init__(self, name: str, confidence: float = 0.5):
        self.name = name
        self.confidence = confidence
        self.success_count = 0
        self.failure_count = 0
        self.total_mutations = 0
        
    @abstractmethod
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply mutation to input data."""
        pass
    
    def update_success_rate(self, success: bool):
        """Update success rate tracking."""
        self.total_mutations += 1
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
    
    def get_success_rate(self) -> float:
        """Get current success rate."""
        if self.total_mutations == 0:
            return 0.0
        return self.success_count / self.total_mutations
    
    def get_adaptive_confidence(self) -> float:
        """Get adaptive confidence based on success rate."""
        base_confidence = self.confidence
        success_rate = self.get_success_rate()
        
        # Adjust confidence based on recent performance
        if self.total_mutations > 10:
            adjustment = (success_rate - 0.5) * 0.3  # Scale adjustment
            return max(0.1, min(0.9, base_confidence + adjustment))
        
        return base_confidence


class RandomMutator(BaseMutator):
    """Random byte-level mutations."""
    
    def __init__(self):
        super().__init__("random", 0.4)
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply random mutations."""
        start_time = time.time()
        
        if not data:
            return MutationResult(False, data, MutationType.RANDOM, 0.0)
        
        mutated = bytearray(data)
        num_mutations = random.randint(1, min(len(data) // 10 + 1, 10))
        
        for _ in range(num_mutations):
            if random.random() < 0.3:  # Insert
                pos = random.randint(0, len(mutated))
                mutated.insert(pos, random.randint(0, 255))
            elif random.random() < 0.6 and len(mutated) > 0:  # Modify
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
            elif len(mutated) > 1:  # Delete
                pos = random.randint(0, len(mutated) - 1)
                del mutated[pos]
        
        generation_time = time.time() - start_time
        size_change = len(mutated) - len(data)
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.RANDOM,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            size_change=size_change,
            metadata={"mutations_applied": num_mutations}
        )


class BitFlipMutator(BaseMutator):
    """Bit-flipping mutations."""
    
    def __init__(self):
        super().__init__("bitflip", 0.6)
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply bit-flipping mutations."""
        start_time = time.time()
        
        if not data:
            return MutationResult(False, data, MutationType.BITFLIP, 0.0)
        
        mutated = bytearray(data)
        
        # Choose bit-flip strategy
        strategy = random.choice(["single_bit", "byte_flip", "multi_bit"])
        
        if strategy == "single_bit":
            # Flip single bits
            num_flips = random.randint(1, min(len(data) * 8 // 100 + 1, 16))
            for _ in range(num_flips):
                byte_pos = random.randint(0, len(mutated) - 1)
                bit_pos = random.randint(0, 7)
                mutated[byte_pos] ^= (1 << bit_pos)
        
        elif strategy == "byte_flip":
            # Flip entire bytes
            num_flips = random.randint(1, min(len(data) // 50 + 1, 8))
            for _ in range(num_flips):
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] ^= 0xFF
        
        else:  # multi_bit
            # Flip multiple consecutive bits
            num_flips = random.randint(1, min(len(data) // 20 + 1, 4))
            for _ in range(num_flips):
                byte_pos = random.randint(0, len(mutated) - 1)
                bit_mask = random.randint(1, 255)
                mutated[byte_pos] ^= bit_mask
        
        generation_time = time.time() - start_time
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.BITFLIP,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            metadata={"strategy": strategy}
        )


class ArithmeticMutator(BaseMutator):
    """Arithmetic mutations on integer values."""
    
    def __init__(self):
        super().__init__("arithmetic", 0.7)
        
        # Interesting arithmetic values
        self.interesting_8bit = [0, 1, 16, 32, 64, 100, 127, 128, 255]
        self.interesting_16bit = [0, 1, 128, 255, 256, 1000, 1024, 32767, 32768, 65535]
        self.interesting_32bit = [0, 1, 32768, 65536, 2147483647, 2147483648, 4294967295]
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply arithmetic mutations."""
        start_time = time.time()
        
        if len(data) < 2:
            return MutationResult(False, data, MutationType.ARITHMETIC, 0.0)
        
        mutated = bytearray(data)
        num_mutations = random.randint(1, min(len(data) // 4, 5))
        
        for _ in range(num_mutations):
            # Choose integer size
            int_size = random.choice([1, 2, 4, 8])
            if len(mutated) < int_size:
                continue
            
            pos = random.randint(0, len(mutated) - int_size)
            
            # Extract current value
            if int_size == 1:
                value = mutated[pos]
                interesting = self.interesting_8bit
                fmt = "B"
            elif int_size == 2:
                value = struct.unpack("<H", mutated[pos:pos+2])[0]
                interesting = self.interesting_16bit
                fmt = "<H"
            elif int_size == 4:
                value = struct.unpack("<I", mutated[pos:pos+4])[0]
                interesting = self.interesting_32bit
                fmt = "<I"
            else:  # 8 bytes
                value = struct.unpack("<Q", mutated[pos:pos+8])[0]
                interesting = self.interesting_32bit  # Reuse 32-bit values
                fmt = "<Q"
            
            # Apply arithmetic operation
            operation = random.choice(["add", "sub", "mul", "interesting", "boundary"])
            
            if operation == "add":
                delta = random.choice([1, -1, 16, -16, 256, -256, 1024, -1024])
                new_value = (value + delta) % (2 ** (int_size * 8))
            elif operation == "sub":
                delta = random.choice([1, -1, 16, -16, 256, -256, 1024, -1024])
                new_value = (value - delta) % (2 ** (int_size * 8))
            elif operation == "mul":
                factor = random.choice([2, 3, 4, 8, 16])
                new_value = (value * factor) % (2 ** (int_size * 8))
            elif operation == "interesting":
                new_value = random.choice(interesting)
            else:  # boundary
                max_val = (2 ** (int_size * 8)) - 1
                new_value = random.choice([0, 1, max_val - 1, max_val, max_val // 2])
            
            # Pack new value back
            try:
                packed = struct.pack(fmt, new_value)
                mutated[pos:pos+int_size] = packed
            except struct.error:
                continue  # Skip if value doesn't fit
        
        generation_time = time.time() - start_time
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.ARITHMETIC,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            metadata={"mutations_applied": num_mutations}
        )


class DictionaryMutator(BaseMutator):
    """Dictionary-based mutations using known strings."""
    
    def __init__(self):
        super().__init__("dictionary", 0.8)
        self._load_dictionaries()
    
    def _load_dictionaries(self):
        """Load mutation dictionaries."""
        self.common_strings = [
            b"admin", b"test", b"user", b"password", b"license", b"key",
            b"config", b"data", b"file", b"temp", b"log", b"debug",
            b"error", b"warning", b"info", b"trace", b"demo", b"trial"
        ]
        
        self.format_strings = [
            b"%s", b"%d", b"%x", b"%p", b"%n", b"{{", b"}}", b"[]",
            b"()", b"<>", b"''", b'""', b"\\", b"/", b"#", b"$"
        ]
        
        self.sql_strings = [
            b"'", b'"', b"--", b"/*", b"*/", b"SELECT", b"INSERT",
            b"UPDATE", b"DELETE", b"DROP", b"UNION", b"OR", b"AND"
        ]
        
        self.web_strings = [
            b"<script>", b"</script>", b"javascript:", b"<img",
            b"onerror=", b"onload=", b"alert(", b"document.cookie"
        ]
        
        self.license_strings = [
            b"LICENSE", b"TRIAL", b"DEMO", b"REGISTERED", b"EXPIRED",
            b"VALID", b"INVALID", b"ACTIVATE", b"SERIAL", b"KEY"
        ]
        
        # Combine all dictionaries
        self.all_strings = (self.common_strings + self.format_strings + 
                          self.sql_strings + self.web_strings + self.license_strings)
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply dictionary-based mutations."""
        start_time = time.time()
        
        if not data:
            return MutationResult(False, data, MutationType.DICTIONARY, 0.0)
        
        mutated = bytearray(data)
        num_mutations = random.randint(1, 3)
        
        # Select appropriate dictionary based on target info
        file_type = target_info.get("file_type", "").lower()
        if "web" in file_type or "http" in file_type:
            dictionary = self.web_strings + self.common_strings
        elif "sql" in file_type or "database" in file_type:
            dictionary = self.sql_strings + self.common_strings
        else:
            dictionary = self.all_strings
        
        for _ in range(num_mutations):
            operation = random.choice(["insert", "replace", "append"])
            string_to_insert = random.choice(dictionary)
            
            if operation == "insert" and len(mutated) > 0:
                pos = random.randint(0, len(mutated))
                mutated[pos:pos] = string_to_insert
            elif operation == "replace" and len(mutated) >= len(string_to_insert):
                pos = random.randint(0, len(mutated) - len(string_to_insert))
                mutated[pos:pos+len(string_to_insert)] = string_to_insert
            else:  # append
                mutated.extend(string_to_insert)
        
        generation_time = time.time() - start_time
        size_change = len(mutated) - len(data)
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.DICTIONARY,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            size_change=size_change,
            metadata={"mutations_applied": num_mutations, "dictionary_used": file_type or "general"}
        )


class SpliceMutator(BaseMutator):
    """Splice mutations combining parts from different inputs."""
    
    def __init__(self):
        super().__init__("splice", 0.6)
        self.corpus_cache = []
    
    def update_corpus(self, corpus: List[bytes]):
        """Update the corpus cache for splicing."""
        self.corpus_cache = corpus[:100]  # Keep recent 100 entries
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply splice mutations."""
        start_time = time.time()
        
        if not data or not self.corpus_cache:
            return MutationResult(False, data, MutationType.SPLICE, 0.0)
        
        # Select random corpus entry for splicing
        donor = random.choice(self.corpus_cache)
        if not donor or len(donor) == 0:
            return MutationResult(False, data, MutationType.SPLICE, 0.0)
        
        mutated = bytearray(data)
        
        # Choose splice strategy
        strategy = random.choice(["head_tail", "middle_insert", "block_replace"])
        
        if strategy == "head_tail":
            # Take head from donor, tail from original
            split_point = random.randint(1, min(len(data), len(donor)) - 1)
            mutated = bytearray(donor[:split_point] + data[split_point:])
        
        elif strategy == "middle_insert":
            # Insert chunk from donor into middle of original
            donor_start = random.randint(0, len(donor) - 1)
            donor_end = min(donor_start + random.randint(1, 64), len(donor))
            insert_pos = random.randint(0, len(mutated))
            
            chunk = donor[donor_start:donor_end]
            mutated[insert_pos:insert_pos] = chunk
        
        else:  # block_replace
            # Replace block in original with block from donor
            if len(mutated) > 4 and len(donor) > 4:
                replace_start = random.randint(0, len(mutated) - 4)
                replace_size = random.randint(1, min(32, len(mutated) - replace_start))
                
                donor_start = random.randint(0, len(donor) - 1)
                donor_end = min(donor_start + replace_size, len(donor))
                
                mutated[replace_start:replace_start+replace_size] = donor[donor_start:donor_end]
        
        generation_time = time.time() - start_time
        size_change = len(mutated) - len(data)
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.SPLICE,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            size_change=size_change,
            metadata={"strategy": strategy, "donor_size": len(donor)}
        )


class StructureAwareMutator(BaseMutator):
    """Structure-aware mutations for known file formats."""
    
    def __init__(self):
        super().__init__("structure_aware", 0.8)
        self._load_format_definitions()
    
    def _load_format_definitions(self):
        """Load file format structure definitions."""
        self.format_definitions = {
            "pe": {
                "magic": b"MZ",
                "fields": [
                    {"name": "e_lfanew", "offset": 0x3C, "size": 4, "type": "uint32"},
                    {"name": "pe_signature", "pe_offset": 0, "size": 4, "type": "signature"}
                ]
            },
            "elf": {
                "magic": b"\x7fELF",
                "fields": [
                    {"name": "e_class", "offset": 4, "size": 1, "type": "enum", "values": [1, 2]},
                    {"name": "e_data", "offset": 5, "size": 1, "type": "enum", "values": [1, 2]},
                    {"name": "e_type", "offset": 16, "size": 2, "type": "uint16"}
                ]
            },
            "pdf": {
                "magic": b"%PDF-",
                "fields": [
                    {"name": "version", "offset": 5, "size": 3, "type": "version"},
                    {"name": "trailer", "pattern": b"trailer", "type": "keyword"}
                ]
            }
        }
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply structure-aware mutations."""
        start_time = time.time()
        
        if not data:
            return MutationResult(False, data, MutationType.STRUCTURE_AWARE, 0.0)
        
        # Detect file format
        file_format = self._detect_format(data)
        if not file_format:
            # Fallback to heuristic mutations
            return await self._heuristic_structure_mutation(data, target_info)
        
        format_def = self.format_definitions[file_format]
        mutated = bytearray(data)
        
        # Apply format-specific mutations
        mutations_applied = 0
        for field in format_def.get("fields", []):
            if random.random() < 0.3:  # 30% chance to mutate each field
                if self._mutate_field(mutated, field):
                    mutations_applied += 1
        
        generation_time = time.time() - start_time
        
        return MutationResult(
            success=mutations_applied > 0,
            data=bytes(mutated),
            mutation_type=MutationType.STRUCTURE_AWARE,
            confidence=self.get_adaptive_confidence(),
            generation_time=generation_time,
            metadata={
                "format": file_format,
                "mutations_applied": mutations_applied
            }
        )
    
    def _detect_format(self, data: bytes) -> Optional[str]:
        """Detect file format based on magic bytes."""
        for format_name, format_def in self.format_definitions.items():
            magic = format_def.get("magic")
            if magic and data.startswith(magic):
                return format_name
        return None
    
    def _mutate_field(self, data: bytearray, field: Dict[str, Any]) -> bool:
        """Mutate a specific field in the structure."""
        try:
            offset = field.get("offset")
            size = field.get("size", 1)
            field_type = field.get("type", "bytes")
            
            if offset is None or offset + size > len(data):
                return False
            
            if field_type == "uint32":
                # Mutate 32-bit integer
                current = struct.unpack("<I", data[offset:offset+4])[0]
                mutations = [current + 1, current - 1, current * 2, 0, 0xFFFFFFFF]
                new_value = random.choice(mutations)
                data[offset:offset+4] = struct.pack("<I", new_value & 0xFFFFFFFF)
                
            elif field_type == "uint16":
                # Mutate 16-bit integer
                current = struct.unpack("<H", data[offset:offset+2])[0]
                mutations = [current + 1, current - 1, 0, 0xFFFF]
                new_value = random.choice(mutations)
                data[offset:offset+2] = struct.pack("<H", new_value & 0xFFFF)
                
            elif field_type == "enum":
                # Mutate enumerated value
                valid_values = field.get("values", [])
                if valid_values:
                    # Sometimes use valid value, sometimes invalid
                    if random.random() < 0.7:
                        new_value = random.choice(valid_values)
                    else:
                        new_value = random.randint(0, 255)
                    data[offset] = new_value
                    
            elif field_type == "version":
                # Mutate version string
                version_chars = b"0123456789."
                for i in range(size):
                    if offset + i < len(data):
                        data[offset + i] = random.choice(version_chars)
            
            return True
            
        except (struct.error, IndexError):
            return False
    
    async def _heuristic_structure_mutation(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply heuristic structure-aware mutations."""
        start_time = time.time()
        mutated = bytearray(data)
        
        # Look for patterns that might be structure-related
        mutations_applied = 0
        
        # Mutate what looks like length fields
        for i in range(0, len(mutated) - 4, 4):
            if random.random() < 0.1:  # 10% chance
                # Check if this could be a length field
                value = struct.unpack("<I", mutated[i:i+4])[0]
                if 0 < value < len(data):
                    # Mutate length value
                    new_value = random.choice([value + 1, value - 1, value * 2, 0])
                    mutated[i:i+4] = struct.pack("<I", new_value & 0xFFFFFFFF)
                    mutations_applied += 1
        
        # Mutate what looks like offsets
        for i in range(0, len(mutated) - 4, 2):
            if random.random() < 0.05:  # 5% chance
                value = struct.unpack("<H", mutated[i:i+2])[0]
                if 0 < value < len(data):
                    new_value = random.choice([value + 4, value - 4, 0])
                    mutated[i:i+2] = struct.pack("<H", new_value & 0xFFFF)
                    mutations_applied += 1
        
        generation_time = time.time() - start_time
        
        return MutationResult(
            success=mutations_applied > 0,
            data=bytes(mutated),
            mutation_type=MutationType.STRUCTURE_AWARE,
            confidence=self.get_adaptive_confidence() * 0.7,  # Lower confidence for heuristic
            generation_time=generation_time,
            metadata={"mutations_applied": mutations_applied, "method": "heuristic"}
        )


class AIGuidedMutator(BaseMutator):
    """AI-guided mutations using learned patterns."""
    
    def __init__(self, ai_enabled: bool = True):
        super().__init__("ai_guided", 0.9)
        self.ai_enabled = ai_enabled
        self.learned_patterns = []
        self.effectiveness_history = {}
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Apply AI-guided mutations."""
        start_time = time.time()
        
        if not self.ai_enabled or not data:
            # Fallback to intelligent heuristic mutation
            return await self._heuristic_ai_mutation(data, target_info)
        
        try:
            # Use AI to analyze the data and suggest mutations
            analysis = await self._analyze_with_ai(data, target_info)
            mutation_strategy = await self._get_ai_mutation_strategy(analysis, target_info)
            
            mutated_data = await self._apply_ai_mutations(data, mutation_strategy)
            
            generation_time = time.time() - start_time
            size_change = len(mutated_data) - len(data)
            
            return MutationResult(
                success=True,
                data=mutated_data,
                mutation_type=MutationType.AI_GUIDED,
                confidence=self.get_adaptive_confidence(),
                generation_time=generation_time,
                size_change=size_change,
                metadata={
                    "ai_strategy": mutation_strategy.get("strategy", "unknown"),
                    "confidence_score": mutation_strategy.get("confidence", 0.5)
                }
            )
            
        except Exception as e:
            logger.warning(f"AI-guided mutation failed, using fallback: {e}")
            return await self._heuristic_ai_mutation(data, target_info)
    
    async def _analyze_with_ai(self, data: bytes, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data using AI to identify mutation opportunities."""
        try:
            # Import AI bridge for real analysis
            from ...hexview.ai_bridge import AIBinaryBridge
            from ...ai.llm_backends import get_llm_manager
            
            # Initialize AI bridge
            llm_manager = get_llm_manager() if hasattr(get_llm_manager, '__call__') else None
            ai_bridge = AIBinaryBridge(llm_manager)
            
            # Analyze data with AI
            ai_result = ai_bridge.analyze_binary_region(data, 0, len(data), 
                                                       "Identify mutation opportunities for fuzzing")
            
            # Extract structured analysis
            structures = []
            interesting_offsets = []
            vulnerability_indicators = []
            
            # Process AI insights
            for insight in ai_result.get("insights", []):
                if insight.get("type") == "STRUCTURE_INFERENCE":
                    structures.append({
                        "offset": insight.get("offset", 0),
                        "size": insight.get("size", 0),
                        "description": insight.get("description", ""),
                        "confidence": insight.get("confidence", 0.5)
                    })
                elif insight.get("type") == "PATTERN_IDENTIFICATION":
                    interesting_offsets.append({
                        "offset": insight.get("offset", 0),
                        "reason": insight.get("description", "Pattern identified"),
                        "confidence": insight.get("confidence", 0.5)
                    })
                elif insight.get("type") == "ANOMALY_DETECTION":
                    vulnerability_indicators.append({
                        "offset": insight.get("offset", 0),
                        "type": "anomaly",
                        "description": insight.get("description", ""),
                        "severity": "medium"
                    })
            
            # Process detected patterns
            for pattern in ai_result.get("patterns", []):
                interesting_offsets.append({
                    "offset": pattern.get("start_offset", 0),
                    "reason": f"Pattern: {pattern.get('pattern_type', 'unknown')}",
                    "confidence": pattern.get("confidence", 0.7)
                })
            
            # Enhanced analysis
            analysis = {
                "data_entropy": self._calculate_entropy(data),
                "suspected_format": target_info.get("file_type", ai_result.get("data_type", "unknown")),
                "potential_structures": structures or self._identify_structures(data),
                "interesting_offsets": interesting_offsets or self._find_interesting_offsets(data),
                "vulnerability_indicators": vulnerability_indicators or self._find_vulnerability_patterns(data),
                "ai_insights": ai_result.get("insights", []),
                "ai_confidence": ai_result.get("confidence", 0.5),
                "mutation_suggestions": self._extract_mutation_suggestions(ai_result)
            }
            
        except Exception as e:
            logger.warning(f"AI analysis failed, using fallback: {e}")
            # Fallback to heuristic analysis
            analysis = {
                "data_entropy": self._calculate_entropy(data),
                "suspected_format": target_info.get("file_type", "unknown"),
                "potential_structures": self._identify_structures(data),
                "interesting_offsets": self._find_interesting_offsets(data),
                "vulnerability_indicators": self._find_vulnerability_patterns(data),
                "ai_insights": [],
                "ai_confidence": 0.3,
                "mutation_suggestions": []
            }
        
        return analysis
    
    async def _get_ai_mutation_strategy(self, analysis: Dict[str, Any], target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI-recommended mutation strategy."""
        # Placeholder for AI strategy selection
        # In a full implementation, this would use LLM to select optimal mutation approach
        
        strategies = ["entropy_targeted", "structure_focused", "vulnerability_directed", "boundary_testing"]
        
        # Select strategy based on analysis
        if analysis.get("data_entropy", 0) < 0.3:
            strategy = "entropy_targeted"
        elif analysis.get("potential_structures"):
            strategy = "structure_focused"
        elif analysis.get("vulnerability_indicators"):
            strategy = "vulnerability_directed"
        else:
            strategy = "boundary_testing"
        
        return {
            "strategy": strategy,
            "confidence": 0.7,
            "target_offsets": analysis.get("interesting_offsets", []),
            "parameters": self._get_strategy_parameters(strategy)
        }
    
    async def _apply_ai_mutations(self, data: bytes, strategy: Dict[str, Any]) -> bytes:
        """Apply mutations based on AI strategy."""
        mutated = bytearray(data)
        strategy_name = strategy.get("strategy", "boundary_testing")
        target_offsets = strategy.get("target_offsets", [])
        
        if strategy_name == "entropy_targeted":
            # Target low-entropy regions for mutation
            mutated = self._mutate_low_entropy_regions(mutated)
            
        elif strategy_name == "structure_focused":
            # Focus on structural elements
            mutated = self._mutate_structural_elements(mutated, target_offsets)
            
        elif strategy_name == "vulnerability_directed":
            # Target potential vulnerability patterns
            mutated = self._mutate_vulnerability_patterns(mutated, target_offsets)
            
        else:  # boundary_testing
            # Test boundary conditions
            mutated = self._mutate_boundaries(mutated)
        
        return bytes(mutated)
    
    async def _heuristic_ai_mutation(self, data: bytes, target_info: Dict[str, Any]) -> MutationResult:
        """Fallback heuristic AI mutation when full AI is not available."""
        start_time = time.time()
        
        if not data:
            return MutationResult(False, data, MutationType.AI_GUIDED, 0.0)
        
        mutated = bytearray(data)
        
        # Apply intelligent heuristics
        # 1. Target areas with repeated patterns
        patterns = self._find_repeated_patterns(data)
        for pattern_info in patterns[:3]:  # Limit to top 3 patterns
            offset = pattern_info["offset"]
            length = pattern_info["length"]
            if offset + length < len(mutated):
                # Mutate the pattern
                for i in range(length):
                    if random.random() < 0.3:
                        mutated[offset + i] = random.randint(0, 255)
        
        # 2. Target potential length/size fields
        for i in range(0, len(mutated) - 4, 4):
            value = struct.unpack("<I", mutated[i:i+4])[0]
            if 4 <= value <= len(data):  # Looks like a reasonable length
                if random.random() < 0.2:
                    new_value = value + random.choice([-1, 1, -4, 4])
                    mutated[i:i+4] = struct.pack("<I", max(0, new_value) & 0xFFFFFFFF)
        
        # 3. Target null bytes (potential padding or separators)
        null_positions = [i for i, b in enumerate(mutated) if b == 0]
        for pos in random.sample(null_positions, min(len(null_positions), 5)):
            mutated[pos] = random.randint(1, 255)
        
        generation_time = time.time() - start_time
        
        return MutationResult(
            success=True,
            data=bytes(mutated),
            mutation_type=MutationType.AI_GUIDED,
            confidence=self.get_adaptive_confidence() * 0.8,  # Slightly lower for heuristic
            generation_time=generation_time,
            metadata={"method": "heuristic", "patterns_found": len(patterns)}
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * np.log2(p)
        
        return entropy / 8.0  # Normalize to 0-1
    
    def _identify_structures(self, data: bytes) -> List[Dict[str, Any]]:
        """Identify potential data structures."""
        structures = []
        
        # Look for repeated sequences that might indicate structures
        min_pattern_size = 4
        max_pattern_size = 64
        
        for pattern_size in range(min_pattern_size, min(max_pattern_size, len(data) // 4)):
            pattern_counts = {}
            for i in range(len(data) - pattern_size + 1):
                pattern = data[i:i+pattern_size]
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            
            # Find patterns that repeat frequently
            for pattern, count in pattern_counts.items():
                if count >= 3:  # Pattern appears at least 3 times
                    structures.append({
                        "pattern": pattern,
                        "size": pattern_size,
                        "count": count,
                        "confidence": min(count / 10.0, 1.0)
                    })
        
        # Sort by confidence
        structures.sort(key=lambda x: x["confidence"], reverse=True)
        return structures[:10]  # Return top 10
    
    def _find_interesting_offsets(self, data: bytes) -> List[int]:
        """Find offsets that might be interesting for mutation."""
        offsets = []
        
        # Add offsets of potential headers/magic bytes
        for i in range(min(64, len(data))):
            if data[i] != 0:  # Non-zero bytes in header region
                offsets.append(i)
        
        # Add offsets of potential length fields
        for i in range(0, len(data) - 4, 4):
            value = struct.unpack("<I", data[i:i+4])[0]
            if 0 < value < len(data):
                offsets.append(i)
        
        # Add offsets of ASCII strings
        current_string_start = None
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if current_string_start is None:
                    current_string_start = i
            else:
                if current_string_start is not None and i - current_string_start >= 4:
                    offsets.append(current_string_start)
                current_string_start = None
        
        return sorted(set(offsets))
    
    def _find_vulnerability_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find patterns that might indicate vulnerability-prone areas."""
        patterns = []
        
        # Look for format string patterns
        format_patterns = [b"%s", b"%d", b"%x", b"%p", b"%n"]
        for pattern in format_patterns:
            offset = data.find(pattern)
            if offset >= 0:
                patterns.append({
                    "type": "format_string",
                    "pattern": pattern,
                    "offset": offset
                })
        
        # Look for potential buffer size indicators
        for i in range(0, len(data) - 4):
            value = struct.unpack("<I", data[i:i+4])[0]
            if value in [256, 512, 1024, 2048, 4096]:  # Common buffer sizes
                patterns.append({
                    "type": "buffer_size",
                    "value": value,
                    "offset": i
                })
        
        return patterns
    
    def _find_repeated_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Find repeated byte patterns in data."""
        patterns = []
        
        for pattern_len in [4, 8, 16]:
            if pattern_len > len(data):
                continue
                
            pattern_positions = {}
            for i in range(len(data) - pattern_len + 1):
                pattern = data[i:i+pattern_len]
                if pattern not in pattern_positions:
                    pattern_positions[pattern] = []
                pattern_positions[pattern].append(i)
            
            # Find patterns that appear multiple times
            for pattern, positions in pattern_positions.items():
                if len(positions) >= 2:
                    patterns.append({
                        "pattern": pattern,
                        "length": pattern_len,
                        "offset": positions[0],
                        "count": len(positions),
                        "positions": positions
                    })
        
        return sorted(patterns, key=lambda x: x["count"], reverse=True)
    
    def _mutate_low_entropy_regions(self, data: bytearray) -> bytearray:
        """Mutate regions with low entropy."""
        # Find regions with many repeated bytes
        for i in range(len(data) - 8):
            window = data[i:i+8]
            if len(set(window)) <= 2:  # Very low entropy
                # Inject some randomness
                for j in range(i, min(i+8, len(data))):
                    if random.random() < 0.5:
                        data[j] = random.randint(0, 255)
        
        return data
    
    def _mutate_structural_elements(self, data: bytearray, offsets: List[int]) -> bytearray:
        """Mutate structural elements at specified offsets."""
        for offset in offsets[:10]:  # Limit mutations
            if offset < len(data):
                if random.random() < 0.5:
                    data[offset] = random.randint(0, 255)
        
        return data
    
    def _mutate_vulnerability_patterns(self, data: bytearray, offsets: List[int]) -> bytearray:
        """Mutate areas that might trigger vulnerabilities."""
        # Focus on areas around format strings and buffer operations
        for offset in offsets:
            if offset + 4 < len(data):
                # Insert potential overflow triggers
                overflow_patterns = [b"A" * 32, b"B" * 64, b"C" * 128]
                pattern = random.choice(overflow_patterns)
                
                # Replace some bytes with overflow pattern
                end_pos = min(offset + len(pattern), len(data))
                data[offset:end_pos] = pattern[:end_pos-offset]
        
        return data
    
    def _mutate_boundaries(self, data: bytearray) -> bytearray:
        """Mutate boundary values and edge cases."""
        # Target integer boundaries
        boundary_values = [0, 1, 127, 128, 255, 256, 65535, 65536]
        
        for i in range(0, len(data) - 4, 4):
            if random.random() < 0.1:
                value = random.choice(boundary_values)
                data[i:i+4] = struct.pack("<I", value & 0xFFFFFFFF)
        
        return data
    
    def _get_strategy_parameters(self, strategy: str) -> Dict[str, Any]:
        """Get parameters for specific mutation strategy."""
        parameters = {
            "entropy_targeted": {"mutation_rate": 0.3, "focus_threshold": 0.2},
            "structure_focused": {"field_mutation_rate": 0.4, "preserve_magic": True},
            "vulnerability_directed": {"overflow_probability": 0.6, "format_string_rate": 0.3},
            "boundary_testing": {"boundary_focus": 0.8, "edge_case_rate": 0.5}
        }
        
        return parameters.get(strategy, {})


class IntelligentMutationEngine:
    """
    Main intelligent mutation engine that coordinates different mutation strategies.
    
    This engine selects the most appropriate mutation strategies based on target
    characteristics, coverage feedback, and AI guidance.
    """
    
    def __init__(self, strategies: List[str], ai_enabled: bool = True):
        """Initialize the mutation engine."""
        self.logger = logging.getLogger(__name__)
        self.ai_enabled = ai_enabled
        self.strategies = strategies
        
        # Initialize mutators
        self.mutators = {}
        self._initialize_mutators()
        
        # Performance tracking
        self.mutation_history = []
        self.strategy_effectiveness = {}
        
        # Adaptive parameters
        self.adaptation_enabled = True
        self.learning_rate = 0.1
        
        self.logger.info(f"Intelligent mutation engine initialized with strategies: {strategies}")
    
    def _initialize_mutators(self):
        """Initialize all available mutators."""
        available_mutators = {
            "random": RandomMutator(),
            "bitflip": BitFlipMutator(),
            "arithmetic": ArithmeticMutator(),
            "dictionary": DictionaryMutator(),
            "splice": SpliceMutator(),
            "structure_aware": StructureAwareMutator(),
            "ai_guided": AIGuidedMutator(self.ai_enabled)
        }
        
        # Only include requested strategies
        for strategy in self.strategies:
            if strategy in available_mutators:
                self.mutators[strategy] = available_mutators[strategy]
        
        # Always include random as fallback
        if "random" not in self.mutators:
            self.mutators["random"] = available_mutators["random"]
        
        self.logger.info(f"Initialized {len(self.mutators)} mutators")
    
    async def mutate(self, data: bytes, target_info: Dict[str, Any], 
                    coverage_feedback: Optional[Dict[str, Any]] = None) -> MutationResult:
        """
        Apply intelligent mutation to input data.
        
        Args:
            data: Input data to mutate
            target_info: Information about the target (file type, architecture, etc.)
            coverage_feedback: Coverage information for guidance
            
        Returns:
            MutationResult with mutated data and metadata
        """
        if not data:
            return MutationResult(False, data, MutationType.RANDOM, 0.0)
        
        # Select mutator based on strategy and feedback
        mutator = self._select_mutator(target_info, coverage_feedback)
        
        # Apply mutation
        try:
            result = await mutator.mutate(data, target_info)
            
            # Update corpus for splice mutator if needed
            if isinstance(mutator, SpliceMutator):
                mutator.update_corpus([data])  # Add current data to corpus
            
            # Record mutation for learning
            self._record_mutation(mutator.name, result, coverage_feedback)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Mutation failed with {mutator.name}: {e}")
            
            # Fallback to random mutation
            fallback_mutator = self.mutators["random"]
            return await fallback_mutator.mutate(data, target_info)
    
    def _select_mutator(self, target_info: Dict[str, Any], 
                       coverage_feedback: Optional[Dict[str, Any]] = None) -> BaseMutator:
        """Select the most appropriate mutator for the current context."""
        
        # If we have coverage feedback, use it to guide selection
        if coverage_feedback and self.adaptation_enabled:
            return self._select_adaptive_mutator(target_info, coverage_feedback)
        
        # Otherwise, use target-based selection
        file_type = target_info.get("file_type", "").lower()
        architecture = target_info.get("architecture", "").lower()
        
        # Prefer structure-aware for known file formats
        if any(fmt in file_type for fmt in ["pe", "elf", "pdf", "zip"]):
            if "structure_aware" in self.mutators:
                return self.mutators["structure_aware"]
        
        # Prefer AI-guided for complex targets
        if self.ai_enabled and "ai_guided" in self.mutators:
            if any(indicator in file_type for indicator in ["protected", "packed", "obfuscated"]):
                return self.mutators["ai_guided"]
        
        # Prefer dictionary for text-based formats
        if any(fmt in file_type for fmt in ["text", "xml", "json", "config"]):
            if "dictionary" in self.mutators:
                return self.mutators["dictionary"]
        
        # Weighted random selection from available mutators
        mutators = list(self.mutators.values())
        weights = [mutator.get_adaptive_confidence() for mutator in mutators]
        
        if sum(weights) == 0:
            return random.choice(mutators)
        
        return random.choices(mutators, weights=weights)[0]
    
    def _select_adaptive_mutator(self, target_info: Dict[str, Any], 
                               coverage_feedback: Dict[str, Any]) -> BaseMutator:
        """Select mutator based on coverage feedback and effectiveness."""
        
        # Analyze coverage feedback
        block_coverage = coverage_feedback.get("block_coverage", 0)
        new_coverage = coverage_feedback.get("new_blocks", 0) > 0
        
        # If we found new coverage recently, favor the strategy that worked
        if new_coverage and self.mutation_history:
            recent_successful = [entry for entry in self.mutation_history[-10:] 
                               if entry.get("found_coverage", False)]
            if recent_successful:
                successful_strategy = recent_successful[-1]["strategy"]
                if successful_strategy in self.mutators:
                    return self.mutators[successful_strategy]
        
        # If coverage is low, prefer exploratory strategies
        if block_coverage < 0.3:
            exploratory_strategies = ["random", "bitflip", "arithmetic"]
            available = [s for s in exploratory_strategies if s in self.mutators]
            if available:
                return self.mutators[random.choice(available)]
        
        # If coverage is high, prefer exploitation strategies
        elif block_coverage > 0.7:
            exploitation_strategies = ["ai_guided", "structure_aware", "dictionary"]
            available = [s for s in exploitation_strategies if s in self.mutators]
            if available:
                return self.mutators[random.choice(available)]
        
        # Default to effectiveness-based selection
        return self._select_by_effectiveness()
    
    def _select_by_effectiveness(self) -> BaseMutator:
        """Select mutator based on historical effectiveness."""
        if not self.strategy_effectiveness:
            # No history yet, random selection
            return random.choice(list(self.mutators.values()))
        
        # Calculate effectiveness scores
        scores = {}
        for strategy, effectiveness in self.strategy_effectiveness.items():
            if strategy in self.mutators:
                # Combine success rate with confidence
                success_rate = effectiveness.get("success_rate", 0)
                confidence = self.mutators[strategy].get_adaptive_confidence()
                scores[strategy] = success_rate * confidence
        
        if not scores:
            return random.choice(list(self.mutators.values()))
        
        # Weighted selection based on scores
        strategies = list(scores.keys())
        weights = list(scores.values())
        
        if sum(weights) == 0:
            return random.choice(list(self.mutators.values()))
        
        selected_strategy = random.choices(strategies, weights=weights)[0]
        return self.mutators[selected_strategy]
    
    def _record_mutation(self, strategy: str, result: MutationResult, 
                        coverage_feedback: Optional[Dict[str, Any]]):
        """Record mutation result for learning and adaptation."""
        
        mutation_record = {
            "timestamp": time.time(),
            "strategy": strategy,
            "success": result.success,
            "confidence": result.confidence,
            "generation_time": result.generation_time,
            "size_change": result.size_change,
            "found_coverage": False
        }
        
        if coverage_feedback:
            mutation_record["found_coverage"] = coverage_feedback.get("new_blocks", 0) > 0
            mutation_record["coverage_gain"] = coverage_feedback.get("new_blocks", 0)
        
        self.mutation_history.append(mutation_record)
        
        # Update strategy effectiveness
        if strategy not in self.strategy_effectiveness:
            self.strategy_effectiveness[strategy] = {
                "total_mutations": 0,
                "successful_mutations": 0,
                "coverage_discoveries": 0,
                "success_rate": 0.0,
                "coverage_rate": 0.0
            }
        
        effectiveness = self.strategy_effectiveness[strategy]
        effectiveness["total_mutations"] += 1
        
        if result.success:
            effectiveness["successful_mutations"] += 1
        
        if mutation_record["found_coverage"]:
            effectiveness["coverage_discoveries"] += 1
        
        # Update rates
        total = effectiveness["total_mutations"]
        effectiveness["success_rate"] = effectiveness["successful_mutations"] / total
        effectiveness["coverage_rate"] = effectiveness["coverage_discoveries"] / total
        
        # Update mutator success tracking
        if strategy in self.mutators:
            self.mutators[strategy].update_success_rate(result.success)
        
        # Keep history manageable
        if len(self.mutation_history) > 1000:
            self.mutation_history = self.mutation_history[-500:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get mutation engine statistics."""
        stats = {
            "total_mutations": len(self.mutation_history),
            "strategy_effectiveness": self.strategy_effectiveness.copy(),
            "mutator_stats": {}
        }
        
        # Add individual mutator statistics
        for name, mutator in self.mutators.items():
            stats["mutator_stats"][name] = {
                "success_rate": mutator.get_success_rate(),
                "confidence": mutator.get_adaptive_confidence(),
                "total_mutations": mutator.total_mutations,
                "successful_mutations": mutator.success_count
            }
        
        return stats
    
    def update_strategies(self, new_strategies: List[str]):
        """Update available mutation strategies."""
        self.strategies = new_strategies
        
        # Reinitialize mutators
        old_mutators = self.mutators.copy()
        self.mutators = {}
        self._initialize_mutators()
        
        # Transfer learning data from old mutators
        for name, old_mutator in old_mutators.items():
            if name in self.mutators:
                new_mutator = self.mutators[name]
                new_mutator.success_count = old_mutator.success_count
                new_mutator.failure_count = old_mutator.failure_count
                new_mutator.total_mutations = old_mutator.total_mutations
        
        self.logger.info(f"Updated mutation strategies: {new_strategies}")
    
    def reset_learning(self):
        """Reset learning and adaptation data."""
        self.mutation_history = []
        self.strategy_effectiveness = {}
        
        # Reset individual mutator statistics
        for mutator in self.mutators.values():
            mutator.success_count = 0
            mutator.failure_count = 0
            mutator.total_mutations = 0
        
        self.logger.info("Reset mutation engine learning data")