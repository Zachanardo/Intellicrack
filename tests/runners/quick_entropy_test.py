#!/usr/bin/env python3
"""Quick entropy analyzer functionality test."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.core.analysis.entropy_analyzer import EntropyAnalyzer
    print("OK Import successful")

    analyzer = EntropyAnalyzer()

    # Quick functionality test
    entropy1 = analyzer.calculate_entropy(b"\x00" * 1000)  # Should be 0
    entropy2 = analyzer.calculate_entropy(bytes(range(256)))  # Should be ~8.0
    entropy3 = analyzer.calculate_entropy(b"\x00\xFF" * 500)  # Should be ~1.0

    print(f"Zero entropy: {entropy1}")
    print(f"Max entropy: {entropy2:.3f}")
    print(f"Binary entropy: {entropy3:.3f}")

    # Classification test
    low = analyzer._classify_entropy(2.0)
    med = analyzer._classify_entropy(6.0)
    high = analyzer._classify_entropy(7.5)

    print(f"Classifications: {low}, {med}, {high}")

    if entropy1 == 0.0 and 7.9 <= entropy2 <= 8.0 and 0.9 <= entropy3 <= 1.1:
        print("OK Basic functionality works!")
    else:
        print("FAIL Functionality test failed")

except Exception as e:
    print(f"FAIL Error: {e}")
    import traceback
    traceback.print_exc()
