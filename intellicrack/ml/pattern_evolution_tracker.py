#!/usr/bin/env python3
"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import hmac
import json
import logging
import multiprocessing as mp
import os
import pickle
import random
import re
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sklearn.cluster import DBSCAN

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.sqlite3_handler import sqlite3

"""
Pattern Evolution Tracker with Adaptive Learning

Advanced pattern evolution system using genetic algorithms and reinforcement learning
to adaptively discover and optimize license protection detection patterns.

Author: Intellicrack Framework
Version: 2.0.0
License: GPL v3
"""

# Security configuration for pickle
PICKLE_SECURITY_KEY = os.environ.get("INTELLICRACK_PICKLE_KEY", "default-key-change-me").encode()


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that only allows safe classes."""

    def find_class(self, module, name):
        """Override ``find_class`` to restrict allowed classes."""
        # Allow only safe modules and classes
        ALLOWED_MODULES = {
            "numpy",
            "numpy.core.multiarray",
            "numpy.core.numeric",
            "pandas",
            "pandas.core.frame",
            "pandas.core.series",
            "sklearn",
            "torch",
            "tensorflow",
            "__builtin__",
            "builtins",
            "collections",
            "collections.abc",
        }

        # Allow model classes from our own modules
        if module.startswith("intellicrack."):
            return super().find_class(module, name)

        # Check if module is in allowed list
        if any(module.startswith(allowed) for allowed in ALLOWED_MODULES):
            return super().find_class(module, name)

        # Deny everything else
        raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")


def secure_pickle_dumps(obj):
    """Securely serialize object with integrity check."""
    # Serialize object
    data = pickle.dumps(obj)

    # Calculate HMAC for integrity
    mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

    # Return MAC + data as bytes
    return mac + data


def secure_pickle_loads(data):
    """Securely deserialize object with integrity verification."""
    # Split MAC and data
    stored_mac = data[:32]  # SHA256 produces 32 bytes
    obj_data = data[32:]

    # Verify integrity
    expected_mac = hmac.new(PICKLE_SECURITY_KEY, obj_data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle data integrity check failed - possible tampering detected")

    # Deserialize object using RestrictedUnpickler
    import io

    return RestrictedUnpickler(io.BytesIO(obj_data)).load()


class PatternType(Enum):
    """Types of patterns that can evolve."""

    BYTE_SEQUENCE = "byte_sequence"
    API_SEQUENCE = "api_sequence"
    STRING_PATTERN = "string_pattern"
    BEHAVIOR_SEQUENCE = "behavior_sequence"
    OPCODE_SEQUENCE = "opcode_sequence"
    ENTROPY_PATTERN = "entropy_pattern"
    CONTROL_FLOW = "control_flow"
    MEMORY_PATTERN = "memory_pattern"


class MutationType(Enum):
    """Types of mutations for genetic algorithm."""

    BIT_FLIP = "bit_flip"
    INSERTION = "insertion"
    DELETION = "deletion"
    SUBSTITUTION = "substitution"
    TRANSPOSITION = "transposition"
    DUPLICATION = "duplication"
    INVERSION = "inversion"
    CROSSOVER = "crossover"


@dataclass
class PatternGene:
    """Represents a single evolvable pattern gene."""

    id: str
    type: PatternType
    pattern_data: Any  # Actual pattern representation
    fitness: float = 0.0
    generation: int = 0
    parent_ids: list[str] = field(default_factory=list)
    mutation_history: list[MutationType] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize pattern gene with generated ID if not provided."""
        if not self.id:
            self.id = self.generate_id()

    def generate_id(self) -> str:
        """Generate unique ID for pattern."""
        data = f"{self.type.value}_{self.pattern_data}_{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def mutate(self, mutation_type: MutationType, mutation_rate: float = 0.1) -> "PatternGene":
        """Create mutated copy of this gene."""
        mutated_data = self._apply_mutation(self.pattern_data, mutation_type, mutation_rate)

        return PatternGene(
            id="",  # Will be auto-generated
            type=self.type,
            pattern_data=mutated_data,
            generation=self.generation + 1,
            parent_ids=[self.id],
            mutation_history=self.mutation_history + [mutation_type],
            metadata=self.metadata.copy(),
        )

    def _apply_mutation(self, data: Any, mutation_type: MutationType, rate: float) -> Any:
        """Apply specific mutation to pattern data."""
        if self.type == PatternType.BYTE_SEQUENCE:
            return self._mutate_byte_sequence(data, mutation_type, rate)
        if self.type == PatternType.API_SEQUENCE:
            return self._mutate_api_sequence(data, mutation_type, rate)
        if self.type == PatternType.STRING_PATTERN:
            return self._mutate_string_pattern(data, mutation_type, rate)
        if self.type == PatternType.OPCODE_SEQUENCE:
            return self._mutate_opcode_sequence(data, mutation_type, rate)
        return data  # No mutation for unsupported types

    def _mutate_byte_sequence(self, data: bytes, mutation_type: MutationType, rate: float) -> bytes:
        """Mutate byte sequence pattern."""
        byte_list = list(data)

        if mutation_type == MutationType.BIT_FLIP:
            for i in range(len(byte_list)):
                if random.random() < rate:  # noqa: S311 - ML pattern mutation probability
                    byte_list[i] ^= 1 << random.randint(0, 7)  # noqa: S311 - ML bit flip mutation

        elif mutation_type == MutationType.INSERTION:
            insert_pos = random.randint(0, len(byte_list))  # noqa: S311 - ML insertion position
            byte_list.insert(insert_pos, random.randint(0, 255))  # noqa: S311 - ML byte insertion

        elif mutation_type == MutationType.DELETION and len(byte_list) > 1:
            del_pos = random.randint(0, len(byte_list) - 1)  # noqa: S311 - ML byte sequence deletion mutation
            del byte_list[del_pos]

        elif mutation_type == MutationType.SUBSTITUTION:
            if byte_list:
                sub_pos = random.randint(0, len(byte_list) - 1)  # noqa: S311 - ML byte sequence substitution position
                byte_list[sub_pos] = random.randint(0, 255)  # noqa: S311 - ML byte sequence substitution value

        elif mutation_type == MutationType.Transposition and len(byte_list) > 1:
            i, j = random.sample(range(len(byte_list)), 2)
            byte_list[i], byte_list[j] = byte_list[j], byte_list[i]

        return bytes(byte_list)

    def _mutate_api_sequence(
        self, data: list[str], mutation_type: MutationType, rate: float
    ) -> list[str]:
        """Mutate API sequence pattern based on mutation rate."""
        api_list = data.copy()

        # Common Windows APIs for mutation pool
        api_pool = [
            "CreateFileA",
            "CreateFileW",
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "GetSystemTime",
            "GetTickCount",
            "IsDebuggerPresent",
            "GetModuleHandleA",
            "GetProcAddress",
            "LoadLibraryA",
            "VirtualProtect",
            "WriteProcessMemory",
            "ReadProcessMemory",
        ]

        # Apply mutation rate - number of mutations to perform
        num_mutations = max(1, int(len(api_list) * rate))

        for _ in range(num_mutations):
            # Only proceed if random chance based on rate allows it
            if random.random() > rate:  # noqa: S311 - ML API mutation probability gating
                continue

            if mutation_type == MutationType.INSERTION and api_pool:
                insert_pos = random.randint(0, len(api_list))  # noqa: S311 - ML API sequence insertion position
                api_list.insert(insert_pos, random.choice(api_pool))  # noqa: S311 - ML API sequence insertion choice

            elif mutation_type == MutationType.DELETION and len(api_list) > 1:
                del_pos = random.randint(0, len(api_list) - 1)  # noqa: S311 - ML API sequence deletion position
                del api_list[del_pos]

            elif mutation_type == MutationType.SUBSTITUTION and api_list and api_pool:
                sub_pos = random.randint(0, len(api_list) - 1)  # noqa: S311 - ML API sequence substitution position
                api_list[sub_pos] = random.choice(api_pool)  # noqa: S311 - ML API sequence substitution choice

        return api_list

    def _mutate_string_pattern(self, data: str, mutation_type: MutationType, rate: float) -> str:
        """Mutate string pattern (regex)."""
        # For regex patterns, we need careful mutations to maintain validity
        if mutation_type == MutationType.SUBSTITUTION:
            # Add optional components
            if "?" not in data and random.random() < rate:  # noqa: S311 - ML string pattern mutation probability
                # Make last character optional
                data = data[:-1] + data[-1] + "?"
            # Add character class
            elif "[" not in data and random.random() < rate:  # noqa: S311 - ML string pattern mutation probability
                # Replace a character with character class
                if len(data) > 0:
                    pos = random.randint(0, len(data) - 1)  # noqa: S311 - ML string pattern character position
                    char = data[pos]
                    if char.isalpha():
                        data = data[:pos] + f"[{char.lower()}{char.upper()}]" + data[pos + 1 :]

        return data

    def _mutate_opcode_sequence(
        self, data: list[str], mutation_type: MutationType, rate: float
    ) -> list[str]:
        """Mutate opcode sequence pattern based on mutation rate."""
        opcode_list = data.copy()

        # Common x86/x64 opcodes for mutation
        opcode_pool = [
            "mov",
            "push",
            "pop",
            "call",
            "jmp",
            "je",
            "jne",
            "cmp",
            "test",
            "xor",
            "add",
            "sub",
            "lea",
            "ret",
            "nop",
        ]

        # Apply mutation rate - number of mutations to perform
        num_mutations = max(1, int(len(opcode_list) * rate))

        for _ in range(num_mutations):
            # Only proceed if random chance based on rate allows it
            if random.random() > rate:  # noqa: S311 - ML opcode mutation probability gating
                continue

            if mutation_type == MutationType.INSERTION and opcode_pool:
                insert_pos = random.randint(0, len(opcode_list))  # noqa: S311 - ML opcode sequence insertion position
                opcode_list.insert(insert_pos, random.choice(opcode_pool))  # noqa: S311 - ML opcode sequence insertion choice

            elif mutation_type == MutationType.DELETION and len(opcode_list) > 1:
                del_pos = random.randint(0, len(opcode_list) - 1)  # noqa: S311 - ML opcode sequence deletion position
                del opcode_list[del_pos]

            elif mutation_type == MutationType.SUBSTITUTION and opcode_list and opcode_pool:
                sub_pos = random.randint(0, len(opcode_list) - 1)  # noqa: S311 - ML opcode sequence substitution position
                opcode_list[sub_pos] = random.choice(opcode_pool)  # noqa: S311 - ML opcode sequence substitution choice

        return opcode_list

    def crossover(
        self, other: "PatternGene", crossover_point: int | None = None
    ) -> tuple["PatternGene", "PatternGene"]:
        """Perform crossover with another gene."""
        if self.type != other.type:
            # Can't crossover different types
            return self, other

        # Single-point crossover
        if self.type == PatternType.BYTE_SEQUENCE:
            data1 = self.pattern_data
            data2 = other.pattern_data

            if not crossover_point:
                crossover_point = random.randint(1, min(len(data1), len(data2)) - 1)  # noqa: S311 - ML genetic algorithm crossover point

            new_data1 = data1[:crossover_point] + data2[crossover_point:]
            new_data2 = data2[:crossover_point] + data1[crossover_point:]

            child1 = PatternGene(
                id="",
                type=self.type,
                pattern_data=new_data1,
                generation=max(self.generation, other.generation) + 1,
                parent_ids=[self.id, other.id],
                mutation_history=[MutationType.CROSSOVER],
            )

            child2 = PatternGene(
                id="",
                type=self.type,
                pattern_data=new_data2,
                generation=max(self.generation, other.generation) + 1,
                parent_ids=[self.id, other.id],
                mutation_history=[MutationType.CROSSOVER],
            )

            return child1, child2

        # For other types, return copies for now
        return self, other


class QLearningAgent:
    """Q-learning agent for pattern effectiveness learning."""

    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.01,
    ):
        """Initialize the Q-learning agent with specified parameters and experience buffer."""
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min

        # Q-table: state -> action -> value
        self.q_table = defaultdict(lambda: np.zeros(action_size))

        # Experience replay buffer
        self.memory = deque(maxlen=10000)

    def get_state_key(self, state: np.ndarray) -> str:
        """Convert state to hashable key."""
        # Discretize continuous values
        discretized = np.round(state, decimals=2)
        return str(discretized.tobytes())

    def act(self, state: np.ndarray) -> int:
        """Choose action using epsilon-greedy policy."""
        if random.random() <= self.epsilon:  # noqa: S311 - ML Q-learning epsilon-greedy exploration
            return random.randint(0, self.action_size - 1)  # noqa: S311 - ML Q-learning random action selection

        state_key = self.get_state_key(state)
        return np.argmax(self.q_table[state_key])

    def remember(
        self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool
    ):
        """Store experience in replay buffer."""
        self.memory.append((state, action, reward, next_state, done))

    def learn(self, batch_size: int = 32):
        """Learn from batch of experiences."""
        if len(self.memory) < batch_size:
            return

        batch = random.sample(self.memory, batch_size)  # noqa: S311 - ML Q-learning experience replay batch sampling

        for state, action, reward, next_state, done in batch:
            state_key = self.get_state_key(state)
            next_state_key = self.get_state_key(next_state)

            target = reward
            if not done:
                target = reward + self.discount_factor * np.max(self.q_table[next_state_key])

            # Q-learning update
            self.q_table[state_key][action] = (1 - self.learning_rate) * self.q_table[state_key][
                action
            ] + self.learning_rate * target

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay


class PatternStorage:
    """SQLite-based pattern storage with versioning."""

    def __init__(self, db_path: str = "pattern_evolution.db"):
        """Initialize pattern storage with SQLite database and thread safety."""
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize database schema."""
        with self.lock:
            cursor = self.conn.cursor()

            # Pattern table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS patterns (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    pattern_data BLOB NOT NULL,
                    fitness REAL DEFAULT 0.0,
                    generation INTEGER DEFAULT 0,
                    parent_ids TEXT,
                    mutation_history TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Pattern performance metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pattern_metrics (
                    pattern_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    true_positives INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    true_negatives INTEGER DEFAULT 0,
                    false_negatives INTEGER DEFAULT 0,
                    detection_time_ms REAL,
                    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
                )
            """)

            # Pattern evolution history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evolution_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_id TEXT,
                    generation INTEGER,
                    fitness REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_type ON patterns(type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_patterns_fitness ON patterns(fitness)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_pattern ON pattern_metrics(pattern_id)"
            )

            self.conn.commit()

    def save_pattern(self, pattern: PatternGene):
        """Save pattern to database."""
        with self.lock:
            cursor = self.conn.cursor()

            # Serialize pattern data
            pattern_blob = secure_pickle_dumps(pattern.pattern_data)
            parent_ids_json = json.dumps(pattern.parent_ids)
            mutation_history_json = json.dumps([m.value for m in pattern.mutation_history])
            metadata_json = json.dumps(pattern.metadata)

            cursor.execute(
                """
                INSERT OR REPLACE INTO patterns
                (id, type, pattern_data, fitness, generation, parent_ids,
                 mutation_history, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (
                    pattern.id,
                    pattern.type.value,
                    pattern_blob,
                    pattern.fitness,
                    pattern.generation,
                    parent_ids_json,
                    mutation_history_json,
                    metadata_json,
                ),
            )

            # Log to evolution history
            cursor.execute(
                """
                INSERT INTO evolution_history (pattern_id, generation, fitness)
                VALUES (?, ?, ?)
            """,
                (pattern.id, pattern.generation, pattern.fitness),
            )

            self.conn.commit()

    def load_pattern(self, pattern_id: str) -> PatternGene | None:
        """Load pattern from database."""
        with self.lock:
            cursor = self.conn.cursor()

            cursor.execute(
                """
                SELECT type, pattern_data, fitness, generation, parent_ids,
                       mutation_history, metadata
                FROM patterns WHERE id = ?
            """,
                (pattern_id,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            (
                type_str,
                pattern_blob,
                fitness,
                generation,
                parent_ids_json,
                mutation_history_json,
                metadata_json,
            ) = row

            pattern = PatternGene(
                id=pattern_id,
                type=PatternType(type_str),
                pattern_data=secure_pickle_loads(pattern_blob),
                fitness=fitness,
                generation=generation,
                parent_ids=json.loads(parent_ids_json),
                mutation_history=[MutationType(m) for m in json.loads(mutation_history_json)],
                metadata=json.loads(metadata_json),
            )

            return pattern

    def get_top_patterns(
        self, pattern_type: PatternType | None = None, limit: int = 10
    ) -> list[PatternGene]:
        """Get top performing patterns."""
        with self.lock:
            cursor = self.conn.cursor()

            if pattern_type:
                cursor.execute(
                    """
                    SELECT id FROM patterns
                    WHERE type = ?
                    ORDER BY fitness DESC
                    LIMIT ?
                """,
                    (pattern_type.value, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id FROM patterns
                    ORDER BY fitness DESC
                    LIMIT ?
                """,
                    (limit,),
                )

            pattern_ids = [row[0] for row in cursor.fetchall()]

        return [self.load_pattern(pid) for pid in pattern_ids if pid]

    def update_metrics(
        self, pattern_id: str, tp: int, fp: int, tn: int, fn: int, detection_time_ms: float
    ):
        """Update pattern performance metrics."""
        with self.lock:
            cursor = self.conn.cursor()

            cursor.execute(
                """
                INSERT INTO pattern_metrics
                (pattern_id, true_positives, false_positives, true_negatives,
                 false_negatives, detection_time_ms)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (pattern_id, tp, fp, tn, fn, detection_time_ms),
            )

            # Update pattern fitness based on metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1_score = (
                2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            )

            # Factor in speed (bonus for faster detection)
            speed_factor = 1.0 / (1.0 + detection_time_ms / 1000.0)  # Normalize to ~0-1

            fitness = f1_score * 0.8 + speed_factor * 0.2

            cursor.execute(
                """
                UPDATE patterns SET fitness = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (fitness, pattern_id),
            )

            self.conn.commit()


class PatternMatcher:
    """Fast pattern matching engine using Bloom filters and optimized algorithms."""

    def __init__(self, bloom_size: int = 1000000, num_hashes: int = 7):
        """Initialize pattern matcher with bloom filter and pattern caching."""
        self.bloom_size = bloom_size
        self.num_hashes = num_hashes
        self.bloom_filter = np.zeros(bloom_size, dtype=bool)
        self.pattern_cache = {}
        self.compiled_patterns = {}

    def add_pattern(self, pattern: PatternGene):
        """Add pattern to matcher."""
        # Add to bloom filter for fast negative checks
        for i in range(self.num_hashes):
            hash_val = hash((pattern.id, i)) % self.bloom_size
            self.bloom_filter[hash_val] = True

        # Cache pattern
        self.pattern_cache[pattern.id] = pattern

        # Pre-compile regex patterns
        if pattern.type == PatternType.STRING_PATTERN:
            try:
                self.compiled_patterns[pattern.id] = re.compile(pattern.pattern_data)
            except re.error as e:
                self.logger.debug("Invalid regex pattern %s: %s", pattern.id, e)

    def match(self, data: bytes, pattern_type: PatternType) -> list[tuple[str, float]]:
        """Match data against patterns, return (``pattern_id``, confidence) tuples."""
        matches = []

        # Quick bloom filter check
        test_hash = hash(data) % self.bloom_size
        if not self.bloom_filter[test_hash]:
            return matches  # Definitely no match

        # Check cached patterns
        for pattern_id, pattern in self.pattern_cache.items():
            if pattern.type != pattern_type:
                continue

            confidence = self._match_pattern(data, pattern)
            if confidence > 0:
                matches.append((pattern_id, confidence))

        # Sort by confidence
        matches.sort(key=lambda x: x[1], reverse=True)

        return matches

    def _match_pattern(self, data: bytes, pattern: PatternGene) -> float:
        """Match specific pattern against data."""
        if pattern.type == PatternType.BYTE_SEQUENCE:
            return self._match_byte_sequence(data, pattern.pattern_data)
        if pattern.type == PatternType.STRING_PATTERN:
            return self._match_string_pattern(data, pattern)
        if pattern.type == PatternType.API_SEQUENCE:
            return self._match_api_sequence(data, pattern.pattern_data)
        if pattern.type == PatternType.OPCODE_SEQUENCE:
            return self._match_opcode_sequence(data, pattern.pattern_data)
        return 0.0

    def _match_byte_sequence(self, data: bytes, pattern: bytes) -> float:
        """Match byte sequence using Boyer-Moore algorithm."""
        if not pattern:
            return 0.0

        # Simple containment check for now
        if pattern in data:
            return 1.0

        # Fuzzy matching: calculate similarity
        min_len = min(len(data), len(pattern))
        if min_len == 0:
            return 0.0

        matches = sum(1 for i in range(min_len) if data[i] == pattern[i])
        return matches / len(pattern)

    def _match_string_pattern(self, data: bytes, pattern: PatternGene) -> float:
        """Match string pattern (regex)."""
        if pattern.id not in self.compiled_patterns:
            return 0.0

        try:
            text = data.decode("utf-8", errors="ignore")
            regex = self.compiled_patterns[pattern.id]

            matches = regex.findall(text)
            if matches:
                # Confidence based on number of matches
                return min(1.0, len(matches) / 10.0)
        except (re.error, KeyError, AttributeError) as e:
            self.logger.debug(f"Failed to match string pattern {pattern.id}: {e}")
        except UnicodeDecodeError as e:
            self.logger.debug(f"Unicode decode error in pattern matching: {e}")

        return 0.0

    def _match_api_sequence(self, data: bytes, pattern: list[str]) -> float:
        """Match API call sequence."""
        # Extract API calls from data (simplified)
        text = data.decode("utf-8", errors="ignore")

        # Look for API names in data
        found_apis = []
        for api in pattern:
            if api in text:
                found_apis.append(api)

        if not pattern:
            return 0.0

        return len(found_apis) / len(pattern)

    def _match_opcode_sequence(self, data: bytes, pattern: list[str]) -> float:
        """Match opcode sequence by analyzing binary data for instruction patterns."""
        if not pattern or not data:
            return 0.0

        # Simple heuristic matching based on common opcode byte patterns
        # In real implementation, this would use a disassembler like Capstone
        opcode_bytes = {
            "mov": [0x89, 0x8B, 0x8A, 0x88, 0xB8, 0xB9, 0xBA, 0xBB],
            "push": [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x68],
            "pop": [0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F],
            "call": [0xE8, 0xFF],
            "jmp": [0xE9, 0xEB, 0xFF],
            "je": [0x74, 0x0F, 0x84],
            "jne": [0x75, 0x0F, 0x85],
            "cmp": [0x39, 0x3B, 0x38, 0x3A, 0x83],
            "test": [0x85, 0x84, 0xF7],
            "xor": [0x31, 0x33, 0x30, 0x32],
            "add": [0x01, 0x03, 0x00, 0x02, 0x83],
            "sub": [0x29, 0x2B, 0x28, 0x2A, 0x83],
            "ret": [0xC3, 0xC2],
            "nop": [0x90],
        }

        matches = 0
        data_bytes = list(data)

        for opcode in pattern:
            if opcode.lower() in opcode_bytes:
                byte_patterns = opcode_bytes[opcode.lower()]
                # Check if any of the opcode's byte patterns exist in data
                for byte_val in byte_patterns:
                    if byte_val in data_bytes:
                        matches += 1
                        break

        # Return confidence as ratio of matched opcodes
        confidence = matches / len(pattern) if pattern else 0.0

        # Add some data-based scoring - longer data might have more patterns
        data_factor = min(1.0, len(data) / 1000.0)  # Normalize by data size

        return min(1.0, confidence * data_factor)


class PatternEvolutionTracker:
    """Main pattern evolution and tracking system."""

    def __init__(
        self,
        db_path: str = "pattern_evolution.db",
        population_size: int = 100,
        elite_size: int = 10,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.7,
    ):
        """Initialize the pattern evolution tracker.

        Sets up the evolutionary machine learning system for tracking and
        evolving binary analysis patterns. Configures genetic algorithm
        parameters, Q-learning agent, and pattern storage backend.

        Args:
            db_path: Path to the pattern database.
            population_size: Size of pattern population for evolution.
            elite_size: Number of elite patterns to preserve.
            mutation_rate: Rate of pattern mutations.
            crossover_rate: Rate of pattern crossover operations.

        """
        self.logger = logging.getLogger(__name__)

        # Configuration
        self.population_size = population_size
        self.elite_size = elite_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate

        # Components
        self.storage = PatternStorage(db_path)
        self.matcher = PatternMatcher()
        self.q_agent = QLearningAgent(state_size=50, action_size=10)

        # Pattern populations by type
        self.populations: dict[PatternType, list[PatternGene]] = {
            ptype: [] for ptype in PatternType
        }

        # Observers for pattern updates
        self.observers = []

        # Thread pool for parallel evaluation
        self.executor = ThreadPoolExecutor(max_workers=mp.cpu_count())

        # Statistics
        self.stats = {
            "generations": 0,
            "total_patterns": 0,
            "best_fitness": 0.0,
            "detections": 0,
            "false_positives": 0,
        }

        # Initialize populations
        self._initialize_populations()

    def _initialize_populations(self):
        """Initialize pattern populations from storage or create new."""
        self.logger.info("Initializing pattern populations")

        # Load existing patterns
        for pattern_type in PatternType:
            stored_patterns = self.storage.get_top_patterns(
                pattern_type,
                self.population_size,
            )

            if len(stored_patterns) < self.population_size:
                # Generate random patterns to fill population
                num_to_generate = self.population_size - len(stored_patterns)
                new_patterns = self._generate_random_patterns(pattern_type, num_to_generate)
                stored_patterns.extend(new_patterns)

            self.populations[pattern_type] = stored_patterns[: self.population_size]

            # Add to matcher
            for pattern in self.populations[pattern_type]:
                self.matcher.add_pattern(pattern)

    def _generate_random_patterns(self, pattern_type: PatternType, count: int) -> list[PatternGene]:
        """Generate random initial patterns."""
        patterns = []

        for _ in range(count):
            if pattern_type == PatternType.BYTE_SEQUENCE:
                # Random byte sequence
                length = random.randint(4, 32)  # noqa: S311 - ML training data byte sequence length generation
                data = bytes([random.randint(0, 255) for _ in range(length)])  # noqa: S311 - ML training data byte generation

            elif pattern_type == PatternType.API_SEQUENCE:
                # Random API sequence
                api_pool = [
                    "CreateFileA",
                    "RegOpenKeyExA",
                    "GetSystemTime",
                    "IsDebuggerPresent",
                    "GetTickCount",
                    "VirtualProtect",
                    "LoadLibraryA",
                    "GetProcAddress",
                    "MessageBoxA",
                ]
                length = random.randint(2, 8)  # noqa: S311 - ML training data API sequence length generation
                data = [random.choice(api_pool) for _ in range(length)]  # noqa: S311 - ML training data API sequence generation

            elif pattern_type == PatternType.STRING_PATTERN:
                # Common license-related regex patterns
                patterns_pool = [
                    r"licen[sc]e",
                    r"serial\s*(?:number|key)",
                    r"registration\s*code",
                    r"trial\s*(?:period|version)",
                    r"evaluation\s*copy",
                    r"unregistered",
                    r"activate",
                    r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}",
                    r"\d{1,2}/\d{1,2}/\d{4}",  # Date pattern
                    r"expire[ds]?",
                ]
                data = random.choice(patterns_pool)  # noqa: S311 - ML training data string pattern generation

            elif pattern_type == PatternType.OPCODE_SEQUENCE:
                # Random opcode sequence
                opcode_pool = [
                    "mov",
                    "push",
                    "pop",
                    "call",
                    "jmp",
                    "je",
                    "jne",
                    "cmp",
                    "test",
                    "xor",
                    "add",
                    "sub",
                    "lea",
                    "ret",
                ]
                length = random.randint(3, 10)  # noqa: S311 - ML training data opcode sequence length generation
                data = [random.choice(opcode_pool) for _ in range(length)]  # noqa: S311 - ML training data opcode sequence generation

            else:
                # Default: empty data
                data = b""

            pattern = PatternGene(
                id="",
                type=pattern_type,
                pattern_data=data,
                generation=0,
            )

            patterns.append(pattern)

        return patterns

    def evolve_generation(self, pattern_type: PatternType | None = None):
        """Evolve one generation of patterns."""
        if pattern_type:
            types_to_evolve = [pattern_type]
        else:
            types_to_evolve = list(PatternType)

        for ptype in types_to_evolve:
            self.logger.info(f"Evolving {ptype.value} patterns")

            population = self.populations[ptype]
            if not population:
                continue

            # Evaluate fitness (parallel)
            futures = []
            for pattern in population:
                future = self.executor.submit(self._evaluate_fitness, pattern)
                futures.append((pattern, future))

            # Collect results
            for pattern, future in futures:
                pattern.fitness = future.result()

            # Sort by fitness
            population.sort(key=lambda p: p.fitness, reverse=True)

            # Select elite
            elite = population[: self.elite_size]

            # Generate new population
            new_population = elite.copy()

            while len(new_population) < self.population_size:
                # Selection
                parent1 = self._tournament_selection(population)
                parent2 = self._tournament_selection(population)

                # Crossover
                if random.random() < self.crossover_rate and parent1.type == parent2.type:  # noqa: S311 - ML genetic algorithm crossover probability
                    child1, child2 = parent1.crossover(parent2)
                    new_population.extend([child1, child2])
                else:
                    new_population.append(parent1)
                    new_population.append(parent2)

                # Mutation
                for i in range(len(new_population) - 2, len(new_population)):
                    if i < len(new_population) and random.random() < self.mutation_rate:  # noqa: S311 - ML genetic algorithm mutation probability
                        mutation_type = random.choice(list(MutationType))  # noqa: S311 - ML genetic algorithm mutation type selection
                        new_population[i] = new_population[i].mutate(
                            mutation_type,
                            self.mutation_rate,
                        )

            # Trim to population size
            new_population = new_population[: self.population_size]

            # Save new patterns
            for pattern in new_population:
                if pattern not in population:  # New pattern
                    self.storage.save_pattern(pattern)
                    self.matcher.add_pattern(pattern)

            # Update population
            self.populations[ptype] = new_population

        self.stats["generations"] += 1
        self._notify_observers()

    def _evaluate_fitness(self, pattern: PatternGene) -> float:
        """Evaluate pattern fitness using stored metrics and pattern characteristics."""
        if not pattern or not pattern.pattern_data:
            return 0.0

        # Base fitness from pattern complexity and type
        complexity_score = 0.0

        if pattern.type == PatternType.BYTE_SEQUENCE:
            # Longer byte sequences are generally more specific
            if isinstance(pattern.pattern_data, bytes):
                complexity_score = min(1.0, len(pattern.pattern_data) / 100.0)

        elif pattern.type == PatternType.API_SEQUENCE:
            # More API calls suggest more complex behavior
            if isinstance(pattern.pattern_data, list):
                complexity_score = min(1.0, len(pattern.pattern_data) / 20.0)

        elif pattern.type == PatternType.STRING_PATTERN:
            # Regex complexity as a proxy for pattern sophistication
            if isinstance(pattern.pattern_data, str):
                regex_features = ["[", "]", "*", "+", "?", "|", "(", ")"]
                feature_count = sum(pattern.pattern_data.count(f) for f in regex_features)
                complexity_score = min(1.0, feature_count / 10.0)

        elif pattern.type == PatternType.OPCODE_SEQUENCE:
            # Instruction sequence diversity
            if isinstance(pattern.pattern_data, list):
                unique_opcodes = len(set(pattern.pattern_data))
                complexity_score = min(1.0, unique_opcodes / 15.0)

        # Factor in generation (older patterns that survived are likely better)
        generation_bonus = min(0.3, pattern.generation * 0.01)

        # Factor in previous fitness if available
        historical_fitness = getattr(pattern, "fitness", 0.0)

        # Combine scores with weights
        final_fitness = complexity_score * 0.5 + generation_bonus * 0.2 + historical_fitness * 0.3

        # Add some randomness for exploration
        final_fitness += random.random() * 0.1  # noqa: S311 - ML fitness evaluation exploration randomness

        return min(1.0, final_fitness)

    def _tournament_selection(
        self, population: list[PatternGene], tournament_size: int = 3
    ) -> PatternGene:
        """Tournament selection for genetic algorithm."""
        tournament = random.sample(population, min(tournament_size, len(population)))  # noqa: S311 - ML genetic algorithm tournament selection
        return max(tournament, key=lambda p: p.fitness)

    def detect(self, data: bytes, pattern_types: list[PatternType] | None = None) -> dict[str, Any]:
        """Detect patterns in data using evolved patterns."""
        if not pattern_types:
            pattern_types = list(PatternType)

        results = {
            "detections": [],
            "confidence": 0.0,
            "patterns_matched": [],
        }

        for ptype in pattern_types:
            matches = self.matcher.match(data, ptype)

            for pattern_id, confidence in matches:
                pattern = self.storage.load_pattern(pattern_id)
                if pattern:
                    results["detections"].append(
                        {
                            "pattern_id": pattern_id,
                            "type": ptype.value,
                            "confidence": confidence,
                            "generation": pattern.generation,
                            "pattern_data": str(pattern.pattern_data)[:100],  # Preview
                        }
                    )
                    results["patterns_matched"].append(pattern_id)

        # Overall confidence
        if results["detections"]:
            results["confidence"] = max(d["confidence"] for d in results["detections"])

        # Update Q-learning agent
        self._update_q_learning(data, results)

        self.stats["detections"] += 1

        return results

    def _update_q_learning(self, data: bytes, results: dict[str, Any]):
        """Update Q-learning agent based on detection results."""
        # Extract features for state
        state = self._extract_state_features(data)

        # Action: which patterns to apply
        action = len(results["patterns_matched"])  # Simplified

        # Reward based on detection confidence
        reward = results["confidence"] * 10

        # Store experience
        self.q_agent.remember(state, action, reward, state, done=True)

        # Learn from experiences
        self.q_agent.learn()

    def _extract_state_features(self, data: bytes) -> np.ndarray:
        """Extract features from data for Q-learning state."""
        features = []

        # Size features
        features.append(len(data))

        # Entropy
        if data:
            byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
            probabilities = byte_counts / len(data)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            features.append(entropy)
        else:
            features.append(0)

        # String features
        text = data.decode("utf-8", errors="ignore")
        features.append(text.count("license"))
        features.append(text.count("serial"))
        features.append(text.count("key"))

        # Pad to state size
        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def feedback(self, pattern_id: str, correct: bool, detection_time_ms: float):
        """Provide feedback on pattern detection."""
        pattern = self.storage.load_pattern(pattern_id)
        if not pattern:
            return

        # Update metrics
        if correct:
            self.storage.update_metrics(
                pattern_id, tp=1, fp=0, tn=0, fn=0, detection_time_ms=detection_time_ms
            )
        else:
            self.storage.update_metrics(
                pattern_id, tp=0, fp=1, tn=0, fn=0, detection_time_ms=detection_time_ms
            )
            self.stats["false_positives"] += 1

        # Reload pattern with updated fitness
        updated_pattern = self.storage.load_pattern(pattern_id)
        if updated_pattern:
            # Update in population
            for ptype in PatternType:
                for i, p in enumerate(self.populations[ptype]):
                    if p.id == pattern_id:
                        self.populations[ptype][i] = updated_pattern
                        break

    def add_observer(self, observer):
        """Add observer for pattern updates."""
        self.observers.append(observer)

    def _notify_observers(self):
        """Notify observers of pattern updates."""
        for observer in self.observers:
            try:
                observer.on_patterns_updated(self)
            except Exception as e:
                self.logger.error(f"Error notifying observer: {e}")

    def export_patterns(self, output_file: str, pattern_type: PatternType | None = None):
        """Export patterns to JSON file."""
        patterns_data = []

        if pattern_type:
            types_to_export = [pattern_type]
        else:
            types_to_export = list(PatternType)

        for ptype in types_to_export:
            for pattern in self.populations[ptype]:
                pattern_dict = {
                    "id": pattern.id,
                    "type": pattern.type.value,
                    "pattern_data": str(pattern.pattern_data),
                    "fitness": pattern.fitness,
                    "generation": pattern.generation,
                    "parent_ids": pattern.parent_ids,
                    "mutation_history": [m.value for m in pattern.mutation_history],
                }
                patterns_data.append(pattern_dict)

        with open(output_file, "w") as f:
            json.dump(
                {
                    "patterns": patterns_data,
                    "stats": self.stats,
                    "timestamp": time.time(),
                },
                f,
                indent=2,
            )

        self.logger.info(f"Exported {len(patterns_data)} patterns to {output_file}")

    def import_patterns(self, input_file: str):
        """Import patterns from JSON file."""
        with open(input_file) as f:
            data = json.load(f)

        imported_count = 0

        for pattern_data in data.get("patterns", []):
            try:
                # Reconstruct pattern
                pattern_type = PatternType(pattern_data["type"])

                # Parse pattern data based on type
                if pattern_type == PatternType.BYTE_SEQUENCE:
                    pattern_data_parsed = bytes.fromhex(pattern_data["pattern_data"])
                elif pattern_type in [PatternType.API_SEQUENCE, PatternType.OPCODE_SEQUENCE]:
                    import ast
                    pattern_data_parsed = ast.literal_eval(pattern_data["pattern_data"])  # List
                else:
                    pattern_data_parsed = pattern_data["pattern_data"]  # String

                pattern = PatternGene(
                    id=pattern_data["id"],
                    type=pattern_type,
                    pattern_data=pattern_data_parsed,
                    fitness=pattern_data["fitness"],
                    generation=pattern_data["generation"],
                    parent_ids=pattern_data["parent_ids"],
                    mutation_history=[MutationType(m) for m in pattern_data["mutation_history"]],
                )

                # Save to storage
                self.storage.save_pattern(pattern)

                # Add to population if high fitness
                if pattern.fitness > 0.5:
                    self.populations[pattern_type].append(pattern)
                    self.matcher.add_pattern(pattern)

                imported_count += 1

            except Exception as e:
                self.logger.error(f"Error importing pattern: {e}")

        self.logger.info(f"Imported {imported_count} patterns from {input_file}")

        # Trim populations to size
        for ptype in PatternType:
            if len(self.populations[ptype]) > self.population_size:
                # Keep best patterns
                self.populations[ptype].sort(key=lambda p: p.fitness, reverse=True)
                self.populations[ptype] = self.populations[ptype][: self.population_size]

    def get_statistics(self) -> dict[str, Any]:
        """Get current statistics."""
        stats = self.stats.copy()

        # Add population statistics
        for ptype in PatternType:
            population = self.populations[ptype]
            if population:
                stats[f"{ptype.value}_count"] = len(population)
                stats[f"{ptype.value}_avg_fitness"] = np.mean([p.fitness for p in population])
                stats[f"{ptype.value}_best_fitness"] = max(p.fitness for p in population)

        return stats

    def cluster_patterns(
        self, pattern_type: PatternType, min_samples: int = 5
    ) -> dict[int, list[PatternGene]]:
        """Cluster similar patterns using DBSCAN."""
        population = self.populations[pattern_type]
        if len(population) < min_samples:
            return {0: population}

        # Extract features for clustering
        features = []
        for pattern in population:
            if pattern_type == PatternType.BYTE_SEQUENCE:
                # Use byte histogram as features
                hist = np.bincount(
                    np.frombuffer(pattern.pattern_data, dtype=np.uint8), minlength=256
                )
                features.append(hist / hist.sum())
            else:
                # Use fitness and generation as simple features
                features.append([pattern.fitness, pattern.generation])

        features = np.array(features)

        # Cluster using DBSCAN
        clustering = DBSCAN(eps=0.3, min_samples=min_samples).fit(features)

        # Group patterns by cluster
        clusters = defaultdict(list)
        for i, label in enumerate(clustering.labels_):
            clusters[label].append(population[i])

        return dict(clusters)

    def shutdown(self):
        """Clean shutdown."""
        self.executor.shutdown(wait=True)
        self.storage.conn.close()


# Example observer implementation
class PatternUpdateObserver:
    """Example observer for pattern updates."""

    def on_patterns_updated(self, tracker: PatternEvolutionTracker):
        """Called when patterns are updated."""
        stats = tracker.get_statistics()
        print(
            f"Generation {stats['generations']}: "
            f"Best fitness: {stats.get('best_fitness', 0):.3f}, "
            f"Detections: {stats['detections']}"
        )


def main():
    """Example usage."""
    import argparse

    parser = argparse.ArgumentParser(description="Pattern Evolution Tracker")
    parser.add_argument("--evolve", type=int, help="Run N evolution generations")
    parser.add_argument("--detect", help="Detect patterns in file")
    parser.add_argument("--export", help="Export patterns to file")
    parser.add_argument("--import", dest="import_file", help="Import patterns from file")
    parser.add_argument("--stats", action="store_true", help="Show statistics")

    args = parser.parse_args()

    # Initialize tracker
    tracker = PatternEvolutionTracker()

    # Add observer
    observer = PatternUpdateObserver()
    tracker.add_observer(observer)

    try:
        if args.evolve:
            print(f"Running {args.evolve} evolution generations...")
            for i in range(args.evolve):
                tracker.evolve_generation()
                print(f"Generation {i+1} complete")

        if args.detect:
            print(f"Detecting patterns in {args.detect}...")
            with open(args.detect, "rb") as f:
                data = f.read()

            results = tracker.detect(data)
            print("Detection results:")
            print(f"  Confidence: {results['confidence']:.3f}")
            print(f"  Patterns matched: {len(results['patterns_matched'])}")

            for detection in results["detections"]:
                print(
                    f"  - {detection['type']}: {detection['confidence']:.3f} "
                    f"(gen {detection['generation']})"
                )

        if args.export:
            tracker.export_patterns(args.export)
            print(f"Patterns exported to {args.export}")

        if args.import_file:
            tracker.import_patterns(args.import_file)
            print(f"Patterns imported from {args.import_file}")

        if args.stats:
            stats = tracker.get_statistics()
            print("\n=== Pattern Evolution Statistics ===")
            for key, value in stats.items():
                print(f"{key}: {value}")

            # Show clustering info
            for ptype in PatternType:
                clusters = tracker.cluster_patterns(ptype)
                if len(clusters) > 1:
                    print(f"\n{ptype.value} clusters: {len(clusters)}")
                    for cluster_id, patterns in clusters.items():
                        print(f"  Cluster {cluster_id}: {len(patterns)} patterns")

    finally:
        tracker.shutdown()


if __name__ == "__main__":
    main()
