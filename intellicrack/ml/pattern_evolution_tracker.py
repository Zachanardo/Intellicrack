#!/usr/bin/env python3
"""Pattern evolution tracker for Intellicrack ML components.

This file is part of Intellicrack.
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
import pickle  # noqa: S403
import random
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar, overload


try:
    from sklearn.cluster import DBSCAN, AgglomerativeClustering, KMeans
    from sklearn.metrics import silhouette_score
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    # Fallback implementations will be defined below

try:
    from scipy.spatial.distance import cosine, hamming, jaccard
    from scipy.stats import chi2_contingency, entropy

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    # Fallback implementations will be defined below

from pathlib import Path

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.sqlite3_handler import sqlite3


logger = logging.getLogger(__name__)

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

# Fallback implementations for missing libraries
if not SKLEARN_AVAILABLE:

    class DBSCAN:
        """Fallback DBSCAN clustering implementation."""

        def __init__(self, eps: float = 0.5, min_samples: int = 5) -> None:
            """Initialize the FallbackDBSCAN clustering algorithm.

            Args:
                eps: The maximum distance between two samples for them to be considered as in the same neighborhood.
                min_samples: The number of samples in a neighborhood for a point to be considered as a core point.

            """
            self.eps = eps
            self.min_samples = min_samples
            self.labels_ = None

        def fit(self, X: np.ndarray) -> "DBSCAN":
            """Fit DBSCAN clustering model.

            Args:
                X: Input data array for clustering.

            Returns:
                Self instance with fitted labels.

            """
            n = len(X)
            self.labels_ = np.zeros(n, dtype=int) - 1
            cluster_id = 0

            for i in range(n):
                if self.labels_[i] != -1:
                    continue

                neighbors = []
                for j in range(n):
                    if i != j:
                        dist = np.linalg.norm(X[i] - X[j])
                        if dist < self.eps:
                            neighbors.append(j)

                if len(neighbors) >= self.min_samples:
                    self.labels_[i] = cluster_id
                    for j in neighbors:
                        if self.labels_[j] == -1:
                            self.labels_[j] = cluster_id
                    cluster_id += 1

            return self

        def fit_predict(self, X: np.ndarray) -> np.ndarray:
            """Fit model and return cluster labels.

            Args:
                X: Input data array for clustering.

            Returns:
                Cluster labels for each sample.

            """
            self.fit(X)
            return self.labels_

    class KMeans:
        """Fallback K-Means clustering implementation."""

        def __init__(self, n_clusters: int = 8, random_state: int | None = None, n_init: int = 10) -> None:
            """Initialize the KMeans clustering algorithm.

            Args:
                n_clusters: The number of clusters to form.
                random_state: Random state for reproducibility.
                n_init: Number of times the k-means algorithm will be run with different centroid seeds.

            """
            self.n_clusters = n_clusters
            self.random_state = random_state
            self.n_init = n_init
            self.labels_ = None

        def fit(self, X: np.ndarray) -> "KMeans":
            """Fit K-Means clustering model.

            Args:
                X: Input data array for clustering.

            Returns:
                Self instance with fitted labels.

            """
            n = len(X)
            self.labels_ = np.random.randint(0, self.n_clusters, n)
            return self

    class AgglomerativeClustering:
        """Fallback agglomerative clustering implementation."""

        def __init__(
            self,
            n_clusters: int | None = None,
            distance_threshold: float | None = None,
            affinity: str = "euclidean",
            linkage: str = "average",
        ) -> None:
            """Initialize the AgglomerativeClustering algorithm.

            Args:
                n_clusters: The number of clusters to find.
                distance_threshold: The linkage distance threshold above which clusters will not be merged.
                affinity: Metric used to compute the linkage.
                linkage: Which linkage criterion to use.

            """
            self.n_clusters = n_clusters
            self.distance_threshold = distance_threshold
            self.affinity = affinity
            self.linkage = linkage
            self.labels_ = None

        def fit_predict(self, X: np.ndarray) -> np.ndarray:
            """Fit model and return cluster labels.

            Args:
                X: Input data array for clustering.

            Returns:
                Cluster labels for each sample.

            """
            n = len(X)
            if self.n_clusters:
                self.labels_ = np.arange(n) % self.n_clusters
            else:
                self.labels_ = np.zeros(n, dtype=int)
            return self.labels_

    class StandardScaler:
        """Fallback standard scaler implementation."""

        def __init__(self) -> None:
            """Initialize the StandardScaler with empty mean and std arrays."""
            self.mean_ = None
            self.std_ = None

        def fit_transform(self, X: np.ndarray) -> np.ndarray:
            """Fit scaler and transform data.

            Args:
                X: Input data array to scale.

            Returns:
                Scaled data normalized to zero mean and unit variance.

            """
            self.mean_ = np.mean(X, axis=0)
            self.std_ = np.std(X, axis=0) + 1e-10
            return (X - self.mean_) / self.std_

    def silhouette_score(X: np.ndarray, labels: np.ndarray) -> float:
        """Fallback silhouette score calculation.

        Args:
            X: Input data array.
            labels: Cluster labels for each sample.

        Returns:
            Silhouette score (fallback returns 0.5).

        """
        return 0.5


if not SCIPY_AVAILABLE:

    def hamming(u: list[float] | np.ndarray | object, v: list[float] | np.ndarray | object) -> float:
        """Hamming distance fallback.

        Args:
            u: First input sequence.
            v: Second input sequence.

        Returns:
            Hamming distance between u and v.

        """
        u_list: list[Any] = u if isinstance(u, list) else list(u)
        v_list: list[Any] = v if isinstance(v, list) else list(v)
        return sum(x != y for x, y in zip(u_list, v_list, strict=False)) / len(u_list)

    def jaccard(u: list[float] | set[Any] | np.ndarray | object, v: list[float] | set[Any] | np.ndarray | object) -> float:
        """Jaccard distance fallback.

        Args:
            u: First input set or sequence.
            v: Second input set or sequence.

        Returns:
            Jaccard distance between u and v.

        """
        set_u: set[Any] = u if isinstance(u, set) else set(u)  # type: ignore[arg-type]
        set_v: set[Any] = v if isinstance(v, set) else set(v)  # type: ignore[arg-type]
        return 1.0 - len(set_u & set_v) / len(set_u | set_v) if (set_u | set_v) else 0.0

    def cosine(u: np.ndarray | list[float] | object, v: np.ndarray | list[float] | object) -> float:
        """Cosine distance fallback.

        Args:
            u: First input vector.
            v: Second input vector.

        Returns:
            Cosine distance between u and v.

        """
        dot_product: Any = np.dot(u, v)  # type: ignore[arg-type]
        norm_u: Any = np.linalg.norm(u)  # type: ignore[arg-type]
        norm_v: Any = np.linalg.norm(v)  # type: ignore[arg-type]
        if norm_u == 0 or norm_v == 0:
            return 1.0
        return float(1.0 - dot_product / (norm_u * norm_v))

    def entropy(pk: np.ndarray | list[float] | object, base: int = 2) -> float:
        """Entropy calculation fallback.

        Args:
            pk: Probability distribution array.
            base: Logarithm base for entropy calculation.

        Returns:
            Entropy of the probability distribution.

        """
        pk_arr: np.ndarray = np.asarray(pk)  # type: ignore[arg-type]
        pk_arr = pk_arr[pk_arr > 0]
        return 0.0 if len(pk_arr) == 0 else float(-np.sum(pk_arr * np.log(pk_arr) / np.log(base)))


class RestrictedUnpickler(pickle.Unpickler):  # noqa: S301
    """Restricted unpickler that only allows safe classes."""

    def find_class(self, module: str, name: str) -> type[Any]:
        """Override ``find_class`` to restrict allowed classes.

        Args:
            module: Module name of the class to unpickle.
            name: Class name to unpickle.

        Returns:
            The class object if allowed.

        Raises:
            pickle.UnpicklingError: If the class is not in the allowed list.

        """
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
            result: type[Any] = super().find_class(module, name)
            return result

        # Check if module is in allowed list
        if any(module.startswith(allowed) for allowed in ALLOWED_MODULES):
            result: type[Any] = super().find_class(module, name)
            return result

        # Deny everything else
        raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")


def secure_pickle_dumps(obj: object) -> bytes:
    """Securely serialize object with integrity check.

    Args:
        obj: Python object to serialize.

    Returns:
        Bytes containing HMAC signature and pickled data.

    """
    # Serialize object
    data = pickle.dumps(obj)

    # Calculate HMAC for integrity
    mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

    # Return MAC + data as bytes
    return mac + data


def secure_pickle_loads(data: bytes) -> object:
    """Securely deserialize object with integrity verification.

    Args:
        data: Bytes containing HMAC signature and pickled data.

    Returns:
        Deserialized Python object.

    Raises:
        ValueError: If integrity verification fails.

    """
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

    def __post_init__(self) -> None:
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
            mutation_history=[*self.mutation_history, mutation_type],
            metadata=self.metadata.copy(),
        )

    def _apply_mutation(self, data: bytes | list[str] | str, mutation_type: MutationType, rate: float) -> Any:
        """Apply specific mutation to pattern data.

        Args:
            data: Pattern data to mutate (bytes, list of strings, or string).
            mutation_type: Type of mutation to apply.
            rate: Mutation rate controlling probability of changes.

        Returns:
            Mutated pattern data of the same type as input.

        """
        if self.type == PatternType.BYTE_SEQUENCE:
            if isinstance(data, bytes):
                return self._mutate_byte_sequence(data, mutation_type, rate)
        elif self.type == PatternType.API_SEQUENCE:
            if isinstance(data, list):
                return self._mutate_api_sequence(data, mutation_type, rate)  # type: ignore[arg-type]
        elif self.type == PatternType.STRING_PATTERN:
            if isinstance(data, str):
                return self._mutate_string_pattern(data, mutation_type, rate)
        elif self.type == PatternType.OPCODE_SEQUENCE:
            if isinstance(data, list):
                return self._mutate_opcode_sequence(data, mutation_type, rate)  # type: ignore[arg-type]
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

        elif mutation_type == MutationType.TRANSPOSITION and len(byte_list) > 1:
            i, j = random.sample(range(len(byte_list)), 2)
            byte_list[i], byte_list[j] = byte_list[j], byte_list[i]

        return bytes(byte_list)

    def _mutate_api_sequence(self, data: list[str], mutation_type: MutationType, rate: float) -> list[str]:
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
            elif "[" not in data and random.random() < rate:  # noqa: S311 - ML string pattern mutation probability
                # Replace a character with character class
                if data:
                    pos = random.randint(0, len(data) - 1)  # noqa: S311 - ML string pattern character position
                    char = data[pos]
                    if char.isalpha():
                        data = f"{data[:pos]}[{char.lower()}{char.upper()}]{data[pos + 1 :]}"

        return data

    def _mutate_opcode_sequence(self, data: list[str], mutation_type: MutationType, rate: float) -> list[str]:
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

    def crossover(self, other: "PatternGene", crossover_point: int | None = None) -> tuple["PatternGene", "PatternGene"]:
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
    ) -> None:
        """Initialize the Q-learning agent with specified parameters and experience buffer."""
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min

        # Q-table: state -> action -> value
        self.q_table: defaultdict[str, np.ndarray] = defaultdict(lambda: np.zeros(action_size))

        # Experience replay buffer
        self.memory: deque[tuple[np.ndarray, int, float, np.ndarray, bool]] = deque(maxlen=10000)

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
        return int(np.argmax(self.q_table[state_key]))

    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool) -> None:
        """Store experience in replay buffer."""
        self.memory.append((state, action, reward, next_state, done))

    def learn(self, batch_size: int = 32) -> None:
        """Learn from batch of experiences."""
        if len(self.memory) < batch_size:
            return

        batch = random.sample(self.memory, batch_size)

        for state, action, reward, next_state, done in batch:
            state_key = self.get_state_key(state)
            next_state_key = self.get_state_key(next_state)

            target = reward
            if not done:
                target = reward + self.discount_factor * np.max(self.q_table[next_state_key])

            # Q-learning update
            self.q_table[state_key][action] = (1 - self.learning_rate) * self.q_table[state_key][action] + self.learning_rate * target

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay


class PatternStorage:
    """SQLite-based pattern storage with versioning."""

    def __init__(self, db_path: str | None = None) -> None:
        """Initialize pattern storage with SQLite database and thread safety."""
        if db_path is None:
            db_path = str(Path(__file__).parent.parent / "data" / "database" / "pattern_evolution.db")
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self) -> None:
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
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_pattern ON pattern_metrics(pattern_id)")

            self.conn.commit()

    def save_pattern(self, pattern: PatternGene) -> None:
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

            return PatternGene(
                id=pattern_id,
                type=PatternType(type_str),
                pattern_data=secure_pickle_loads(pattern_blob),
                fitness=fitness,
                generation=generation,
                parent_ids=json.loads(parent_ids_json),
                mutation_history=[MutationType(m) for m in json.loads(mutation_history_json)],
                metadata=json.loads(metadata_json),
            )

    def get_top_patterns(self, pattern_type: PatternType | None = None, limit: int = 10) -> list[PatternGene]:
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

        loaded_patterns: list[PatternGene] = []
        for pid in pattern_ids:
            if pid:
                if loaded := self.load_pattern(pid):
                    loaded_patterns.append(loaded)
        return loaded_patterns

    def update_metrics(self, pattern_id: str, tp: int, fp: int, tn: int, fn: int, detection_time_ms: float) -> None:
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
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

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

    def __init__(self, bloom_size: int = 1000000, num_hashes: int = 7) -> None:
        """Initialize pattern matcher with bloom filter and pattern caching."""
        self.logger = logging.getLogger(__name__)
        self.bloom_size = bloom_size
        self.num_hashes = num_hashes
        self.bloom_filter = np.zeros(bloom_size, dtype=bool)
        self.pattern_cache: dict[str, PatternGene] = {}
        self.compiled_patterns: dict[str, re.Pattern[str]] = {}

    def add_pattern(self, pattern: PatternGene) -> None:
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
            except re.error:
                self.logger.debug("Invalid regex pattern %s", pattern.id, exc_info=True)

    def match(self, data: bytes, pattern_type: PatternType) -> list[tuple[str, float]]:
        """Match data against patterns, return (``pattern_id``, confidence) tuples."""
        matches: list[tuple[str, float]] = []

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

        matches = sum(data[i] == pattern[i] for i in range(min_len))
        return matches / len(pattern)

    def _match_string_pattern(self, data: bytes, pattern: PatternGene) -> float:
        """Match string pattern (regex)."""
        if pattern.id not in self.compiled_patterns:
            return 0.0

        try:
            text = data.decode("utf-8", errors="ignore")
            regex = self.compiled_patterns[pattern.id]

            if matches := regex.findall(text):
                # Confidence based on number of matches
                return min(1.0, len(matches) / 10.0)
        except (re.error, KeyError, AttributeError):
            self.logger.debug("Failed to match string pattern %s", pattern.id, exc_info=True)
        except UnicodeDecodeError:
            self.logger.debug("Unicode decode error in pattern matching", exc_info=True)

        return 0.0

    def _match_api_sequence(self, data: bytes, pattern: list[str]) -> float:
        """Match API call sequence."""
        # Extract API calls from data (simplified)
        text = data.decode("utf-8", errors="ignore")

        found_apis = [api for api in pattern if api in text]
        return len(found_apis) / len(pattern) if pattern else 0.0

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
    """Run pattern evolution and tracking system."""

    def __init__(
        self,
        db_path: str | None = None,
        population_size: int = 100,
        elite_size: int = 10,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.7,
    ) -> None:
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

        # Advanced pattern learning components
        # Removed out-of-scope ML components

        # Pattern family tracker
        self.pattern_families: defaultdict[str, set[str]] = defaultdict(set)  # family_id -> set of pattern_ids
        self.family_representatives: dict[str, str] = {}  # family_id -> representative pattern_id

        # Pattern populations by type
        self.populations: dict[PatternType, list[PatternGene]] = {ptype: [] for ptype in PatternType}

        # Observers for pattern updates
        self.observers: list[PatternUpdateObserver] = []

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

    def _initialize_populations(self) -> None:
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
                length = secrets.randbelow(29) + 4
                data = bytes(secrets.randbelow(256) for _ in range(length))

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
                length = secrets.randbelow(7) + 2
                data_api: list[str] = [secrets.choice(api_pool) for _ in range(length)]
                data = data_api

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
                data_str: str = secrets.choice(patterns_pool)
                data = data_str

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
                length = secrets.randbelow(8) + 3
                data_opcode: list[str] = [secrets.choice(opcode_pool) for _ in range(length)]
                data = data_opcode

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

    def _calculate_pattern_similarity(self, pattern1: PatternGene, pattern2: PatternGene) -> float:
        """Calculate similarity between two patterns."""
        # Use chi2_contingency for calculating similarity if available
        if SCIPY_AVAILABLE and pattern1.type == PatternType.STRING_PATTERN and pattern2.type == PatternType.STRING_PATTERN:
            # Create contingency table for chi2 test
            try:
                # Extract common features for both patterns
                pattern1_features: set[Any] = set(pattern1.pattern_data)
                pattern2_features: set[Any] = set(pattern2.pattern_data)

                # Create a simple contingency table
                intersection = len(pattern1_features & pattern2_features)
                only_in_p1 = len(pattern1_features - pattern2_features)
                only_in_p2 = len(pattern2_features - pattern1_features)
                neither = 0  # For this simple case, assume all items are in at least one set

                # Create contingency table
                contingency_table = np.array([[intersection, only_in_p2], [only_in_p1, neither + 1]])  # Adding 1 to avoid zero issues

                # Calculate chi2 contingency if possible
                _chi2, p_value, _dof, _expected = chi2_contingency(contingency_table)

                # Use 1-p_value as a similarity measure (higher value means more similar)
                similarity = max(0.0, 1 - float(p_value))
                return min(similarity, 1.0)
            except Exception:
                self.logger.debug("Chi2 calculation failed, using fallback", exc_info=True)

        return self._calculate_basic_similarity(pattern1, pattern2)

    def _calculate_basic_similarity(self, pattern1: PatternGene, pattern2: PatternGene) -> float:
        """Calculate basic similarity between two patterns."""
        if pattern1.type != pattern2.type:
            return 0.0

        if pattern1.type == PatternType.BYTE_SEQUENCE:
            if isinstance(pattern1.pattern_data, bytes) and isinstance(pattern2.pattern_data, bytes):
                min_len = min(len(pattern1.pattern_data), len(pattern2.pattern_data))
                if min_len == 0:
                    return 0.0
                matches = sum(pattern1.pattern_data[i] == pattern2.pattern_data[i] for i in range(min_len))
                return matches / max(len(pattern1.pattern_data), len(pattern2.pattern_data))

        elif pattern1.type == PatternType.API_SEQUENCE:
            if isinstance(pattern1.pattern_data, list) and isinstance(pattern2.pattern_data, list):
                set1 = set(pattern1.pattern_data)
                set2 = set(pattern2.pattern_data)
                return 0.0 if not set1 or not set2 else len(set1 & set2) / len(set1 | set2)
        elif pattern1.type == PatternType.STRING_PATTERN:
            if isinstance(pattern1.pattern_data, str) and isinstance(pattern2.pattern_data, str):
                if pattern1.pattern_data == pattern2.pattern_data:
                    return 1.0
                min_len = min(len(pattern1.pattern_data), len(pattern2.pattern_data))
                if min_len == 0:
                    return 0.0
                matches = sum(pattern1.pattern_data[i] == pattern2.pattern_data[i] for i in range(min_len))
                return matches / max(len(pattern1.pattern_data), len(pattern2.pattern_data))

        return 0.5

    def detect_pattern_mutations(self, pattern: PatternGene) -> list[dict[str, Any]]:
        """Detect mutations in a pattern compared to its parents."""
        mutations: list[dict[str, Any]] = []

        for parent_id in pattern.parent_ids:
            if parent := self.storage.load_pattern(parent_id):
                mutation_info = self._detect_mutation(parent, pattern)
                mutations.append({"parent_id": parent_id, "mutation_info": mutation_info})

        return mutations

    def _detect_mutation(self, parent: PatternGene, child: PatternGene) -> dict[str, Any]:
        """Detect mutation between parent and child patterns."""
        return {
            "similarity": self._calculate_basic_similarity(parent, child),
            "generation_diff": child.generation - parent.generation,
            "fitness_diff": child.fitness - parent.fitness,
            "mutations": child.mutation_history[-1:],
        }

    def cluster_into_families(self, pattern_type: PatternType, similarity_threshold: float = 0.7) -> dict[str, set[str]]:
        """Cluster patterns into families based on similarity."""
        population = self.populations[pattern_type]
        if not population:
            return {}

        # Build similarity matrix
        n = len(population)
        similarity_matrix = np.zeros((n, n))

        for i in range(n):
            for j in range(i + 1, n):
                sim = self._calculate_pattern_similarity(population[i], population[j])
                similarity_matrix[i][j] = sim
                similarity_matrix[j][i] = sim

        # Hierarchical clustering based on similarity
        distance_matrix = 1.0 - similarity_matrix
        clustering = AgglomerativeClustering(
            n_clusters=None,
            distance_threshold=1.0 - similarity_threshold,
            affinity="precomputed",
            linkage="average",
        )
        labels = clustering.fit_predict(distance_matrix)

        # Group patterns into families
        families = defaultdict(set)
        for i, label in enumerate(labels):
            family_id = f"{pattern_type.value}_family_{label}"
            families[family_id].add(population[i].id)
            self.pattern_families[family_id].add(population[i].id)

        # Select family representatives (highest fitness in each family)
        for family_id, pattern_ids in families.items():
            if patterns := [p for p in population if p.id in pattern_ids]:
                representative = max(patterns, key=lambda p: p.fitness)
                self.family_representatives[family_id] = representative.id

        return dict(families)

    def analyze_temporal_evolution(self, pattern_type: PatternType) -> dict[str, Any]:
        """Analyze temporal evolution patterns."""
        population = self.populations[pattern_type]

        if not population:
            return {
                "evolution_rate": {"rate": 0.0, "acceleration": 0.0},
                "evolutionary_branches": [],
                "prediction": {},
                "active_lineages": 0,
                "pattern_type": pattern_type.value,
            }

        avg_generation = sum(p.generation for p in population) / len(population)
        avg_fitness = sum(p.fitness for p in population) / len(population)

        parent_ids: set[str] = set()
        for pattern in population:
            parent_ids.update(pattern.parent_ids)

        return {
            "evolution_rate": {
                "rate": avg_generation / max(1, self.stats["generations"]),
                "acceleration": avg_fitness,
            },
            "evolutionary_branches": list(parent_ids),
            "prediction": {
                "expected_fitness": avg_fitness * 1.1,
                "expected_generation": avg_generation + 1,
            },
            "active_lineages": len(parent_ids),
            "pattern_type": pattern_type.value,
        }

    def evolve_generation(self, pattern_type: PatternType | None = None) -> None:
        """Evolve one generation of patterns with advanced learning."""
        types_to_evolve = [pattern_type] if pattern_type else list(PatternType)
        for ptype in types_to_evolve:
            self.logger.info("Evolving %s patterns", ptype.value)

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

        # Perform advanced pattern learning after evolution
        for ptype in types_to_evolve:
            # Detect mutations in new patterns
            for pattern in self.populations[ptype]:
                if pattern.parent_ids:
                    if mutations := self.detect_pattern_mutations(pattern):
                        pattern.metadata["detected_mutations"] = mutations

            # Cluster into families
            families = self.cluster_into_families(ptype)
            self.logger.info("Identified %d pattern families for %s", len(families), ptype.value)

            # Analyze temporal evolution
            temporal_analysis = self.analyze_temporal_evolution(ptype)
            self.logger.info(
                "Evolution rate for %s: %.4f (acceleration: %.4f)",
                ptype.value,
                temporal_analysis["evolution_rate"]["rate"],
                temporal_analysis["evolution_rate"]["acceleration"],
            )

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

    def _tournament_selection(self, population: list[PatternGene], tournament_size: int = 3) -> PatternGene:
        """Tournament selection for genetic algorithm."""
        tournament = random.sample(population, min(tournament_size, len(population)))
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
                if pattern := self.storage.load_pattern(pattern_id):
                    detections_list: list[dict[str, Any]] = results["detections"]  # type: ignore[assignment]
                    detections_list.append(
                        {
                            "pattern_id": pattern_id,
                            "type": ptype.value,
                            "confidence": confidence,
                            "generation": pattern.generation,
                            "pattern_data": str(pattern.pattern_data)[:100],  # Preview
                        },
                    )
                    patterns_matched_list: list[str] = results["patterns_matched"]  # type: ignore[assignment]
                    patterns_matched_list.append(pattern_id)

        if detections_list_final := results["detections"]:
            results["confidence"] = max(float(d["confidence"]) for d in detections_list_final)

        # Update Q-learning agent
        self._update_q_learning(data, results)

        self.stats["detections"] += 1

        return results

    def _update_q_learning(self, data: bytes, results: dict[str, Any]) -> None:
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
        features = [len(data)]

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
        features.extend((text.count("license"), text.count("serial"), text.count("key")))
        # Pad to state size
        while len(features) < 50:
            features.append(0)

        return np.array(features[:50])

    def feedback(self, pattern_id: str, correct: bool, detection_time_ms: float) -> None:
        """Provide feedback on pattern detection."""
        pattern = self.storage.load_pattern(pattern_id)
        if not pattern:
            return

        # Update metrics
        if correct:
            self.storage.update_metrics(pattern_id, tp=1, fp=0, tn=0, fn=0, detection_time_ms=detection_time_ms)
        else:
            self.storage.update_metrics(pattern_id, tp=0, fp=1, tn=0, fn=0, detection_time_ms=detection_time_ms)
            self.stats["false_positives"] += 1

        if updated_pattern := self.storage.load_pattern(pattern_id):
            # Update in population
            for ptype in PatternType:
                for i, p in enumerate(self.populations[ptype]):
                    if p.id == pattern_id:
                        self.populations[ptype][i] = updated_pattern
                        break

    def add_observer(self, observer: "PatternUpdateObserver") -> None:
        """Add observer for pattern updates.

        Args:
            observer: Observer instance to register for updates.

        """
        self.observers.append(observer)

    def _notify_observers(self) -> None:
        """Notify observers of pattern updates."""
        for observer in self.observers:
            try:
                observer.on_patterns_updated(self)
            except Exception:
                self.logger.exception("Error notifying observer")

    def export_patterns(self, output_file: str, pattern_type: PatternType | None = None) -> None:
        """Export patterns to JSON file."""
        patterns_data = []

        types_to_export = [pattern_type] if pattern_type else list(PatternType)
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

        self.logger.info("Exported %d patterns to %s", len(patterns_data), output_file)

    def import_patterns(self, input_file: str) -> None:
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

            except Exception:
                self.logger.exception("Error importing pattern")

        self.logger.info("Imported %d patterns from %s", imported_count, input_file)

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
            if population := self.populations[ptype]:
                stats[f"{ptype.value}_count"] = len(population)
                stats[f"{ptype.value}_avg_fitness"] = np.mean([p.fitness for p in population])
                stats[f"{ptype.value}_best_fitness"] = max(p.fitness for p in population)

        return stats

    def cluster_patterns(self, pattern_type: PatternType, min_samples: int = 5) -> dict[int, list[PatternGene]]:
        """Cluster similar patterns using DBSCAN."""
        population = self.populations[pattern_type]
        if len(population) < min_samples:
            return {0: population}

        # Extract features for clustering
        features = []
        for pattern in population:
            if pattern_type == PatternType.BYTE_SEQUENCE:
                # Use byte histogram as features
                hist = np.bincount(np.frombuffer(pattern.pattern_data, dtype=np.uint8), minlength=256)
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

    def shutdown(self) -> None:
        """Clean shutdown."""
        self.executor.shutdown(wait=True)
        self.storage.conn.close()


# Example observer implementation
class PatternUpdateObserver:
    """Demonstrate observer for pattern updates."""

    def __init__(self) -> None:
        """Initialize the observer with a logger."""
        self.logger = logging.getLogger(__name__)

    def on_patterns_updated(self, tracker: PatternEvolutionTracker) -> None:
        """Handle pattern updates."""
        stats = tracker.get_statistics()
        self.logger.info(
            "Generation %d: Best fitness: %.3f, Detections: %d",
            stats["generations"],
            stats.get("best_fitness", 0),
            stats["detections"],
        )


def main() -> None:
    """Run the pattern evolution command-line interface."""
    import argparse

    main_logger = logging.getLogger(__name__)

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
            main_logger.info("Running %d evolution generations...", args.evolve)
            for i in range(args.evolve):
                tracker.evolve_generation()
                main_logger.info("Generation %d complete", i + 1)

        if args.detect:
            main_logger.info("Detecting patterns in %s...", args.detect)
            with open(args.detect, "rb") as f:
                data = f.read()

            results = tracker.detect(data)
            main_logger.info("Detection results:")
            main_logger.info("  Confidence: %.3f", results["confidence"])
            main_logger.info("  Patterns matched: %d", len(results["patterns_matched"]))

            for detection in results["detections"]:
                main_logger.info(
                    "  - %s: %.3f (gen %d)",
                    detection["type"],
                    detection["confidence"],
                    detection["generation"],
                )

        if args.export:
            tracker.export_patterns(args.export)
            main_logger.info("Patterns exported to %s", args.export)

        if args.import_file:
            tracker.import_patterns(args.import_file)
            main_logger.info("Patterns imported from %s", args.import_file)

        if args.stats:
            stats = tracker.get_statistics()
            main_logger.info("=== Pattern Evolution Statistics ===")
            for key, value in stats.items():
                main_logger.info("%s: %s", key, value)

            # Show clustering info
            for ptype in PatternType:
                clusters = tracker.cluster_patterns(ptype)
                if len(clusters) > 1:
                    main_logger.info("%s clusters: %d", ptype.value, len(clusters))
                    for cluster_id, patterns in clusters.items():
                        main_logger.info("  Cluster %s: %d patterns", cluster_id, len(patterns))

    finally:
        tracker.shutdown()


if __name__ == "__main__":
    main()
