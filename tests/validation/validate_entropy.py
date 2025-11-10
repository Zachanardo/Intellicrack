#!/usr/bin/env python3
"""Direct validation of entropy analyzer functionality."""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer
import tempfile
import random
import math

def validate_entropy_analyzer():
    """Validate core entropy analyzer functionality."""
    print("=== ENTROPY ANALYZER VALIDATION ===")

    analyzer = EntropyAnalyzer()

    # Test 1: Basic entropy calculation
    print("\n1. Testing basic entropy calculations...")

    # Perfect order (0 entropy)
    data = b"\x00" * 1000
    entropy = analyzer.calculate_entropy(data)
    print(f"   All zeros: {entropy:.6f} (expected: 0.0)")
    assert entropy == 0.0

    # Perfect randomness (8.0 entropy)
    data = bytes(range(256))
    entropy = analyzer.calculate_entropy(data)
    print(f"   All bytes: {entropy:.6f} (expected: ~8.0)")
    assert 7.99 < entropy <= 8.0

    # Two equal bytes (1.0 entropy)
    data = b"\x00\xFF" * 500
    entropy = analyzer.calculate_entropy(data)
    print(f"   Two bytes: {entropy:.6f} (expected: ~1.0)")
    assert 0.99 < entropy <= 1.01

    print("   OK Basic entropy calculations PASSED")

    # Test 2: Classification
    print("\n2. Testing entropy classification...")

    assert analyzer._classify_entropy(2.0) == "low"
    assert analyzer._classify_entropy(6.0) == "medium"
    assert analyzer._classify_entropy(7.5) == "high"

    print("   OK Entropy classification PASSED")

    # Test 3: File analysis
    print("\n3. Testing file analysis...")

    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"Test data for file analysis " * 100)
        tf.flush()

        result = analyzer.analyze_entropy(tf.name)

        assert "overall_entropy" in result
        assert "file_size" in result
        assert "entropy_classification" in result
        assert "analysis_status" in result
        assert result["analysis_status"] == "completed"

        print(f"   File entropy: {result['overall_entropy']:.3f}")
        print(f"   Classification: {result['entropy_classification']}")
        print(f"   File size: {result['file_size']} bytes")

        os.unlink(tf.name)

    print("   OK File analysis PASSED")

    # Test 4: Error handling
    print("\n4. Testing error handling...")

    result = analyzer.analyze_entropy("nonexistent_file.bin")
    assert "error" in result
    print("   OK Error handling PASSED")

    # Test 5: Real-world data patterns
    print("\n5. Testing real-world patterns...")

    # Compressed-like data
    import zlib
    original = b"This is some text to compress. " * 100
    compressed = zlib.compress(original, level=9)
    entropy = analyzer.calculate_entropy(compressed)
    print(f"   Compressed data: {entropy:.3f}")
    assert entropy > 6.0

    # Random data
    random.seed(42)
    random_data = bytes([random.randint(0, 255) for _ in range(1000)])
    entropy = analyzer.calculate_entropy(random_data)
    print(f"   Random data: {entropy:.3f}")
    assert entropy > 7.0

    print("   OK Real-world patterns PASSED")

    print("\n=== ALL VALIDATIONS PASSED ===")
    print("OK Entropy analyzer is working correctly!")

    return True

if __name__ == "__main__":
    try:
        validate_entropy_analyzer()
        print("\n🎉 ENTROPY ANALYZER VALIDATION COMPLETE")
    except Exception as e:
        print(f"\nFAIL VALIDATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
