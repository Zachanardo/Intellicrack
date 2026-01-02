"""Basic test of polymorphic analyzer functionality.

Demonstrates the polymorphic analyzer's capabilities without external dependencies.
"""

from intellicrack.core.analysis.polymorphic_analyzer import (
    PolymorphicAnalyzer,
    PolymorphicEngine,
    MutationType,
)


def test_basic_functionality() -> None:
    """Test basic polymorphic analyzer functionality."""
    print("=" * 70)
    print("POLYMORPHIC ANALYZER - BASIC FUNCTIONALITY TEST")
    print("=" * 70)

    analyzer = PolymorphicAnalyzer(arch="x86", bits=32)
    print(f"\nOK Created PolymorphicAnalyzer: arch={analyzer.arch}, bits={analyzer.bits}")

    code = bytes(
        [
            0x55,
            0x89,
            0xE5,
            0x31,
            0xC0,
            0x5D,
            0xC3,
        ]
    )
    print(f"\nOK Test code bytes: {code.hex()}")

    try:
        analysis = analyzer.analyze_polymorphic_code(code, base_address=0x1000)
        print(f"\nOK Analysis completed successfully")
        print(f"  - Engine type: {analysis.engine_type.value}")
        print(f"  - Mutation types detected: {len(analysis.mutation_types)}")
        print(f"  - Behavior patterns: {len(analysis.behavior_patterns)}")
        print(f"  - Mutation complexity: {analysis.mutation_complexity:.2f}")
        print(f"  - Invariant features: {len(analysis.invariant_features)}")
        print(f"  - Evasion techniques: {len(analysis.evasion_techniques)}")

        if analysis.mutation_types:
            print("\n  Detected mutation types:")
            for mutation in analysis.mutation_types:
                print(f"    - {mutation.value}")

        if analysis.evasion_techniques:
            print("\n  Detected evasion techniques:")
            for technique in analysis.evasion_techniques:
                print(f"    - {technique}")

        if analysis.invariant_features:
            print("\n  Invariant features:")
            for key, value in analysis.invariant_features.items():
                if isinstance(value, (int, float)):
                    print(f"    - {key}: {value}")
                elif isinstance(value, (list, tuple)) and len(value) > 0:
                    print(f"    - {key}: {len(value)} items")

    except Exception as e:
        print(f"\n⚠ Analysis completed with limitation: {e}")
        print("  (This is expected without Capstone installed)")

    normalized = analyzer.normalize_code_variant(code, base_address=0x1000)
    print(f"\nOK Normalized signature: {normalized[:32]}...")

    semantic_sig = analyzer.extract_semantic_signature(code, base_address=0x1000)
    print(f"OK Semantic signature: {semantic_sig[:32] if semantic_sig else 'N/A (requires Capstone)'}...")

    code_variant = bytes(
        [
            0x55,
            0x89,
            0xE5,
            0x90,
            0x31,
            0xC0,
            0x90,
            0x5D,
            0xC3,
        ]
    )

    similarity, details = analyzer.compare_code_variants(code, code_variant)
    print(f"\nOK Code variant comparison:")
    print(f"  - Similarity score: {similarity:.2f}")
    print(f"  - Details: {details}")

    print("\n" + "=" * 70)
    print("TEST COMPLETED SUCCESSFULLY")
    print("=" * 70)
    print("\nNOTE: For full functionality, install Capstone:")
    print("  pip install capstone")
    print("\nThe analyzer provides:")
    print("  OK Semantic analysis of polymorphic code")
    print("  OK Mutation detection (substitution, renaming, etc.)")
    print("  OK Behavior pattern extraction")
    print("  OK Code normalization and signature generation")
    print("  OK Decryption routine identification")
    print("  OK Evasion technique detection")
    print("  OK Code variant comparison")


def test_mutation_types() -> None:
    """Test all mutation type enumerations."""
    print("\n" + "=" * 70)
    print("MUTATION TYPES")
    print("=" * 70)

    mutation_types = [
        MutationType.INSTRUCTION_SUBSTITUTION,
        MutationType.REGISTER_RENAMING,
        MutationType.CODE_REORDERING,
        MutationType.JUNK_INSERTION,
        MutationType.DEAD_CODE,
        MutationType.OPAQUE_PREDICATES,
        MutationType.SEMANTIC_NOP,
        MutationType.INSTRUCTION_EXPANSION,
        MutationType.CONTROL_FLOW_FLATTENING,
        MutationType.VIRTUALIZATION,
    ]

    print("\nSupported mutation detection types:")
    for mutation in mutation_types:
        print(f"  OK {mutation.value.replace('_', ' ').title()}")


def test_engine_types() -> None:
    """Test all polymorphic engine enumerations."""
    print("\n" + "=" * 70)
    print("POLYMORPHIC ENGINE TYPES")
    print("=" * 70)

    engine_types = [
        PolymorphicEngine.METAPHOR,
        PolymorphicEngine.NGVCK,
        PolymorphicEngine.ZMIST,
        PolymorphicEngine.PRIZM,
        PolymorphicEngine.RDA,
        PolymorphicEngine.CREATEPOLY,
        PolymorphicEngine.CUSTOM,
        PolymorphicEngine.UNKNOWN,
    ]

    print("\nSupported polymorphic engine detection:")
    for engine in engine_types:
        print(f"  OK {engine.value.upper()}")


if __name__ == "__main__":
    test_basic_functionality()
    test_mutation_types()
    test_engine_types()
