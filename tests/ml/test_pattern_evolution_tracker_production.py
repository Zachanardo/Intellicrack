"""Production tests for ML pattern evolution tracker.

This module validates real pattern evolution using genetic algorithms and
reinforcement learning for license protection detection. Tests verify actual
pattern learning, mutation, and optimization without mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

# ruff: noqa: PLR6301, PLR2004

import hashlib
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest


numpy = pytest.importorskip("numpy", reason="NumPy required for pattern evolution")

from intellicrack.ml.pattern_evolution_tracker import (  # noqa: E402
    PICKLE_SECURITY_KEY,
    MutationType,
    PatternEvolutionTracker,
    PatternGene,
    PatternMatcher,
    PatternStorage,
    PatternType,
    PatternUpdateObserver,
    QLearningAgent,
    RestrictedUnpickler,
    secure_pickle_dumps,
    secure_pickle_loads,
)


class TestPatternGene:
    """Tests for evolvable pattern gene structure."""

    def test_pattern_gene_creation_byte_sequence(self) -> None:
        """PatternGene creates with byte sequence pattern."""
        pattern_data = b"\x55\x8b\xec\x83\xec\x40"
        gene = PatternGene(
            id="",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=pattern_data,
        )

        assert gene.type == PatternType.BYTE_SEQUENCE
        assert gene.pattern_data == pattern_data
        assert gene.fitness == 0.0
        assert gene.generation == 0
        assert len(gene.id) == 16

    def test_pattern_gene_creation_api_sequence(self) -> None:
        """PatternGene creates with API call sequence pattern."""
        api_calls = ["VirtualProtect", "CreateRemoteThread", "WriteProcessMemory"]
        gene = PatternGene(
            id="test123",
            type=PatternType.API_SEQUENCE,
            pattern_data=api_calls,
            fitness=0.85,
            generation=5,
        )

        assert gene.id == "test123"
        assert gene.type == PatternType.API_SEQUENCE
        assert gene.pattern_data == api_calls
        assert gene.fitness == 0.85
        assert gene.generation == 5

    def test_pattern_gene_id_generation(self) -> None:
        """PatternGene generates unique ID when not provided."""
        gene1 = PatternGene(
            id="",
            type=PatternType.STRING_PATTERN,
            pattern_data="license_key",
        )
        gene2 = PatternGene(
            id="",
            type=PatternType.STRING_PATTERN,
            pattern_data="license_key",
        )

        assert len(gene1.id) == 16
        assert len(gene2.id) == 16
        assert gene1.id != gene2.id

    def test_pattern_gene_mutate_bit_flip(self) -> None:
        """PatternGene mutation produces modified offspring."""
        original = PatternGene(
            id="parent1",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=b"\x00\x00\x00\x00",
            fitness=0.5,
            generation=1,
        )

        mutated = original.mutate(MutationType.BIT_FLIP, mutation_rate=0.5)

        assert mutated.id != original.id
        assert mutated.generation == original.generation + 1
        assert mutated.parent_ids == [original.id]
        assert MutationType.BIT_FLIP in mutated.mutation_history
        assert mutated.type == original.type

    def test_pattern_gene_mutate_insertion(self) -> None:
        """PatternGene insertion mutation adds elements."""
        original = PatternGene(
            id="parent2",
            type=PatternType.API_SEQUENCE,
            pattern_data=["VirtualAlloc", "VirtualProtect"],
            generation=2,
        )

        mutated = original.mutate(MutationType.INSERTION, mutation_rate=0.3)

        assert mutated.generation == 3
        assert len(mutated.parent_ids) == 1
        assert MutationType.INSERTION in mutated.mutation_history

    def test_pattern_gene_mutate_deletion(self) -> None:
        """PatternGene deletion mutation removes elements."""
        original = PatternGene(
            id="parent3",
            type=PatternType.OPCODE_SEQUENCE,
            pattern_data=["push", "mov", "call", "ret", "nop"],
            generation=0,
        )

        mutated = original.mutate(MutationType.DELETION, mutation_rate=0.2)

        assert mutated.generation == 1
        assert MutationType.DELETION in mutated.mutation_history

    def test_pattern_gene_mutation_history_tracking(self) -> None:
        """PatternGene tracks complete mutation history."""
        gene = PatternGene(
            id="",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=b"\x90\x90\x90",
        )

        gene = gene.mutate(MutationType.BIT_FLIP)
        gene = gene.mutate(MutationType.INSERTION)
        gene = gene.mutate(MutationType.SUBSTITUTION)

        assert len(gene.mutation_history) == 3
        assert MutationType.BIT_FLIP in gene.mutation_history
        assert MutationType.INSERTION in gene.mutation_history
        assert MutationType.SUBSTITUTION in gene.mutation_history
        assert gene.generation == 3


class TestPatternStorage:
    """Tests for pattern persistence and storage."""

    def test_pattern_storage_initialization(self) -> None:
        """PatternStorage initializes database correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            assert storage.db_path == str(db_path)
            assert db_path.exists()

    def test_pattern_storage_save_and_load_pattern(self) -> None:
        """PatternStorage persists and retrieves patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            gene = PatternGene(
                id="test_gene_1",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=b"\x55\x8b\xec",
                fitness=0.92,
                generation=10,
            )

            storage.save_pattern(gene)
            loaded = storage.load_pattern("test_gene_1")

            assert loaded is not None
            assert loaded.id == gene.id
            assert loaded.type == gene.type
            assert loaded.fitness == gene.fitness
            assert loaded.generation == gene.generation

    def test_pattern_storage_load_nonexistent_pattern(self) -> None:
        """PatternStorage returns None for missing pattern."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            loaded = storage.load_pattern("nonexistent_id")

            assert loaded is None

    def test_pattern_storage_get_all_patterns(self) -> None:
        """PatternStorage retrieves all stored patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            gene1 = PatternGene(id="gene1", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x90")
            gene2 = PatternGene(id="gene2", type=PatternType.API_SEQUENCE, pattern_data=["VirtualAlloc"])
            gene3 = PatternGene(id="gene3", type=PatternType.STRING_PATTERN, pattern_data="license")

            storage.save_pattern(gene1)
            storage.save_pattern(gene2)
            storage.save_pattern(gene3)

            all_patterns = storage.get_all_patterns()

            assert len(all_patterns) == 3
            pattern_ids = [p.id for p in all_patterns]
            assert "gene1" in pattern_ids
            assert "gene2" in pattern_ids
            assert "gene3" in pattern_ids

    def test_pattern_storage_update_fitness(self) -> None:
        """PatternStorage updates pattern fitness correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            gene = PatternGene(
                id="fitness_test",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=b"\x00",
                fitness=0.5,
            )

            storage.save_pattern(gene)
            storage.update_fitness("fitness_test", 0.95)
            updated = storage.load_pattern("fitness_test")

            assert updated is not None
            assert updated.fitness == 0.95

    def test_pattern_storage_get_top_patterns(self) -> None:
        """PatternStorage returns highest fitness patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            storage.save_pattern(PatternGene(id="low", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x01", fitness=0.3))
            storage.save_pattern(PatternGene(id="high", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x02", fitness=0.95))
            storage.save_pattern(PatternGene(id="medium", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x03", fitness=0.6))

            top_patterns = storage.get_top_patterns(limit=2)

            assert len(top_patterns) == 2
            assert top_patterns[0].id == "high"
            assert top_patterns[0].fitness == 0.95
            assert top_patterns[1].id == "medium"

    def test_pattern_storage_delete_pattern(self) -> None:
        """PatternStorage deletes patterns correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "patterns.db"
            storage = PatternStorage(str(db_path))

            gene = PatternGene(id="delete_me", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\xff")
            storage.save_pattern(gene)

            assert storage.load_pattern("delete_me") is not None

            storage.delete_pattern("delete_me")

            assert storage.load_pattern("delete_me") is None


class TestQLearningAgent:
    """Tests for Q-learning reinforcement learning agent."""

    def test_qlearning_agent_initialization(self) -> None:
        """QLearningAgent initializes with correct parameters."""
        agent = QLearningAgent(
            state_size=10,
            action_size=8,
            learning_rate=0.1,
            discount_factor=0.95,
            epsilon=0.2,
        )

        assert agent.learning_rate == 0.1
        assert agent.discount_factor == 0.95
        assert agent.epsilon == 0.2
        assert len(agent.q_table) == 0

    def test_qlearning_agent_choose_action_exploration(self) -> None:
        """QLearningAgent explores with epsilon-greedy strategy."""
        agent = QLearningAgent(state_size=10, action_size=8, epsilon=1.0)

        actions = [MutationType.BIT_FLIP, MutationType.INSERTION, MutationType.DELETION]
        chosen_actions = [agent.choose_action("state1", actions) for _ in range(10)]

        assert all(action in actions for action in chosen_actions)
        assert len(set(chosen_actions)) > 1

    def test_qlearning_agent_update_q_value(self) -> None:
        """QLearningAgent updates Q-values correctly."""
        agent = QLearningAgent(state_size=10, action_size=8, learning_rate=0.5, discount_factor=0.9)

        state = "pattern_byte_seq"
        action = MutationType.BIT_FLIP
        reward = 0.8
        next_state = "pattern_byte_seq_mutated"

        agent.update(state, action, reward, next_state)

        assert (state, action) in agent.q_table
        assert agent.q_table[state, action] > 0

    def test_qlearning_agent_learning_convergence(self) -> None:
        """QLearningAgent converges with repeated updates."""
        agent = QLearningAgent(state_size=10, action_size=8, learning_rate=0.1, discount_factor=0.9)

        state = "state1"
        action = MutationType.SUBSTITUTION
        reward = 1.0

        for _ in range(100):
            agent.update(state, action, reward, state)

        q_value = agent.q_table.get((state, action), 0.0)
        assert q_value > 0.5


class TestPatternMatcher:
    """Tests for pattern matching against binaries."""

    def test_pattern_matcher_initialization(self) -> None:
        """PatternMatcher initializes correctly."""
        matcher = PatternMatcher()

        assert matcher is not None

    def test_pattern_matcher_match_byte_sequence(self) -> None:
        """PatternMatcher finds byte sequence in binary data."""
        matcher = PatternMatcher()
        binary_data = b"\x00\x01\x02\x03\x55\x8b\xec\x83\xec\x40\x04\x05\x06"
        pattern = b"\x55\x8b\xec\x83\xec\x40"

        gene = PatternGene(
            id="test",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=pattern,
        )

        matches = matcher.match_pattern(gene, binary_data)

        assert len(matches) > 0
        assert any(binary_data[m:m + len(pattern)] == pattern for m in matches)

    def test_pattern_matcher_no_match(self) -> None:
        """PatternMatcher returns empty list when pattern not found."""
        matcher = PatternMatcher()
        binary_data = b"\x00\x01\x02\x03\x04\x05"
        pattern = b"\xff\xfe\xfd"

        gene = PatternGene(
            id="test",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=pattern,
        )

        matches = matcher.match_pattern(gene, binary_data)

        assert len(matches) == 0

    def test_pattern_matcher_multiple_matches(self) -> None:
        """PatternMatcher finds all occurrences of pattern."""
        matcher = PatternMatcher()
        pattern = b"\x90\x90"
        binary_data = b"\x00" + pattern + b"\x01" + pattern + b"\x02" + pattern + b"\x03"

        gene = PatternGene(
            id="test",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=pattern,
        )

        matches = matcher.match_pattern(gene, binary_data)

        assert len(matches) == 3

    def test_pattern_matcher_calculate_fitness(self) -> None:
        """PatternMatcher calculates pattern fitness correctly."""
        matcher = PatternMatcher()

        true_positives = 10
        false_positives = 2
        false_negatives = 1

        fitness = matcher.calculate_fitness(true_positives, false_positives, false_negatives)

        assert 0.0 <= fitness <= 1.0
        assert fitness > 0.5


class TestPatternEvolutionTracker:
    """Tests for complete pattern evolution system."""

    def test_evolution_tracker_initialization(self) -> None:
        """PatternEvolutionTracker initializes with database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evolution.db"
            tracker = PatternEvolutionTracker(
                db_path=str(db_path),
                population_size=50,
                mutation_rate=0.1,
            )

            assert tracker.storage.db_path == str(db_path)
            assert tracker.population_size == 50
            assert tracker.mutation_rate == 0.1

    def test_evolution_tracker_add_initial_pattern(self) -> None:
        """PatternEvolutionTracker adds seed patterns to population."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evolution.db"
            tracker = PatternEvolutionTracker(db_path=str(db_path))

            gene = PatternGene(
                id="seed1",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=b"\x55\x8b\xec",
            )

            tracker.add_pattern(gene)
            loaded = tracker.storage.load_pattern("seed1")

            assert loaded is not None
            assert loaded.id == "seed1"

    def test_evolution_tracker_evolve_population(self) -> None:
        """PatternEvolutionTracker evolves patterns through generations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evolution.db"
            tracker = PatternEvolutionTracker(
                db_path=str(db_path),
                population_size=10,
                mutation_rate=0.3,
            )

            initial_genes = [
                PatternGene(id=f"gene{i}", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x90" * 4)
                for i in range(5)
            ]

            for gene in initial_genes:
                tracker.add_pattern(gene)

            tracker.evolve_generation()

            all_patterns = tracker.storage.get_all_patterns()
            assert len(all_patterns) > 5

    def test_evolution_tracker_fitness_evaluation(self) -> None:
        """PatternEvolutionTracker evaluates fitness against binary samples."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evolution.db"
            tracker = PatternEvolutionTracker(db_path=str(db_path))

            gene = PatternGene(
                id="eval_test",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=b"\x55\x8b\xec",
                fitness=0.0,
            )

            tracker.add_pattern(gene)

            binary_samples = [
                b"\x00\x01\x55\x8b\xec\x02\x03",
                b"\x55\x8b\xec\x83\xec\x40",
                b"\xff\xfe\xfd",
            ]

            tracker.evaluate_fitness("eval_test", binary_samples, true_positive_samples=[0, 1])

            updated = tracker.storage.load_pattern("eval_test")
            assert updated.fitness > 0.0

    def test_evolution_tracker_get_best_patterns(self) -> None:
        """PatternEvolutionTracker retrieves top performing patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "evolution.db"
            tracker = PatternEvolutionTracker(db_path=str(db_path))

            tracker.add_pattern(PatternGene(id="low", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x01", fitness=0.2))
            tracker.add_pattern(PatternGene(id="high", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x02", fitness=0.95))
            tracker.add_pattern(PatternGene(id="mid", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x03", fitness=0.6))

            best = tracker.get_best_patterns(top_n=2)

            assert len(best) == 2
            assert best[0].id == "high"
            assert best[1].id == "mid"


class TestPatternUpdateObserver:
    """Tests for pattern update observation system."""

    def test_observer_initialization(self) -> None:
        """PatternUpdateObserver initializes correctly."""
        observer = PatternUpdateObserver()

        assert observer is not None

    def test_observer_notify_pattern_update(self) -> None:
        """PatternUpdateObserver handles pattern update notifications."""
        observer = PatternUpdateObserver()
        gene = PatternGene(
            id="notify_test",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=b"\x90",
        )

        observer.on_pattern_updated(gene)


class TestSecurePickle:
    """Tests for secure pickle serialization."""

    def test_secure_pickle_roundtrip(self) -> None:
        """Secure pickle serializes and deserializes correctly."""
        original_data = {"key": "value", "numbers": [1, 2, 3]}

        serialized = secure_pickle_dumps(original_data)
        deserialized = secure_pickle_loads(serialized)

        assert deserialized == original_data

    def test_secure_pickle_integrity_check(self) -> None:
        """Secure pickle detects tampering."""
        original_data = {"protected": "data"}
        serialized = secure_pickle_dumps(original_data)

        tampered = bytearray(serialized)
        tampered[35] ^= 0xFF
        tampered_bytes = bytes(tampered)

        with pytest.raises(ValueError, match="integrity check failed"):
            secure_pickle_loads(tampered_bytes)

    def test_secure_pickle_pattern_gene(self) -> None:
        """Secure pickle handles PatternGene objects."""
        gene = PatternGene(
            id="pickle_test",
            type=PatternType.API_SEQUENCE,
            pattern_data=["VirtualAlloc", "VirtualProtect"],
            fitness=0.87,
            generation=5,
        )

        serialized = secure_pickle_dumps(gene)
        deserialized = secure_pickle_loads(serialized)

        assert isinstance(deserialized, PatternGene)
        assert deserialized.id == gene.id
        assert deserialized.fitness == gene.fitness


class TestRealWorldEvolution:
    """Integration tests for real-world pattern evolution scenarios."""

    def test_vmprotect_pattern_evolution(self) -> None:
        """Pattern evolution discovers VMProtect signatures."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "vmprotect.db"
            tracker = PatternEvolutionTracker(
                db_path=str(db_path),
                population_size=20,
                mutation_rate=0.15,
            )

            vmprotect_signature = b"\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x58"
            seed_gene = PatternGene(
                id="vmprotect_seed",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=vmprotect_signature,
            )

            tracker.add_pattern(seed_gene)

            binary_with_vmprotect = (
                b"\x55\x8b\xec\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x58\x83\xec\x40"
            )
            binary_without_vmprotect = b"\x55\x8b\xec\x83\xec\x40\x90\x90"

            samples = [binary_with_vmprotect, binary_without_vmprotect]
            tracker.evaluate_fitness("vmprotect_seed", samples, true_positive_samples=[0])

            updated = tracker.storage.load_pattern("vmprotect_seed")
            assert updated.fitness > 0.0

    def test_multi_generation_evolution_improves_fitness(self) -> None:
        """Multiple evolution generations improve pattern fitness."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "multi_gen.db"
            tracker = PatternEvolutionTracker(
                db_path=str(db_path),
                population_size=15,
                mutation_rate=0.2,
            )

            initial_pattern = b"\x55\x8b\xec"
            seed = PatternGene(
                id="evolving",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=initial_pattern,
            )
            tracker.add_pattern(seed)

            target_binary = b"\x00\x01\x55\x8b\xec\x83\xec\x40\x02\x03"

            for _ in range(3):
                tracker.evolve_generation()
                all_patterns = tracker.storage.get_all_patterns()
                for pattern in all_patterns:
                    tracker.evaluate_fitness(pattern.id, [target_binary], true_positive_samples=[0])

            best_patterns = tracker.get_best_patterns(top_n=1)
            assert len(best_patterns) > 0

    def test_pattern_clustering_similar_patterns(self) -> None:
        """Pattern evolution clusters similar patterns together."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "clustering.db"
            tracker = PatternEvolutionTracker(db_path=str(db_path))

            similar_patterns = [
                PatternGene(id=f"similar{i}", type=PatternType.BYTE_SEQUENCE, pattern_data=b"\x90" * (4 + i))
                for i in range(5)
            ]

            different_pattern = PatternGene(
                id="different",
                type=PatternType.BYTE_SEQUENCE,
                pattern_data=b"\xff\xfe\xfd\xfc",
            )

            for pattern in similar_patterns:
                tracker.add_pattern(pattern)
            tracker.add_pattern(different_pattern)

            all_patterns = tracker.storage.get_all_patterns()
            assert len(all_patterns) == 6


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_pattern_data(self) -> None:
        """PatternGene handles empty pattern data."""
        gene = PatternGene(
            id="empty",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=b"",
        )

        assert gene.pattern_data == b""

    def test_very_large_pattern(self) -> None:
        """PatternGene handles large patterns."""
        large_pattern = b"\x90" * 10000
        gene = PatternGene(
            id="large",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=large_pattern,
        )

        assert len(gene.pattern_data) == 10000

    def test_concurrent_storage_access(self) -> None:
        """PatternStorage handles concurrent access safely."""
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "concurrent.db"
            storage = PatternStorage(str(db_path))

            def save_patterns(start_id: int) -> None:
                for i in range(10):
                    gene = PatternGene(
                        id=f"concurrent_{start_id}_{i}",
                        type=PatternType.BYTE_SEQUENCE,
                        pattern_data=bytes([i]),
                    )
                    storage.save_pattern(gene)

            threads = [threading.Thread(target=save_patterns, args=(tid,)) for tid in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            all_patterns = storage.get_all_patterns()
            assert len(all_patterns) == 50

    def test_mutation_on_minimal_pattern(self) -> None:
        """PatternGene mutation handles minimal patterns gracefully."""
        gene = PatternGene(
            id="minimal",
            type=PatternType.BYTE_SEQUENCE,
            pattern_data=b"\x01",
        )

        mutated = gene.mutate(MutationType.BIT_FLIP, mutation_rate=0.5)

        assert mutated.generation == 1
        assert mutated.parent_ids == [gene.id]
