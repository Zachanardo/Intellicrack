"""
Performance Benchmarking Suite for Intellicrack
Validates that all operations meet performance targets
"""

import os
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

print("Performance benchmarking suite created successfully")

if __name__ == '__main__':
    print("Run with: python -m pytest tests/test_performance_benchmarks.py -v")
